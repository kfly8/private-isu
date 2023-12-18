package Isuconp;
use v5.38;
use utf8;

use Kossy;

use HTTP::Status qw(:constants);
use Plack::Session;
use Plack::App::File;
use DBIx::Sunny;
use String::ShellQuote qw(shell_quote);
use Log::Minimal qw(infof warnf critf);
use Crypt::URandom qw(urandom);
use Text::Xslate;

use constant POSTS_PER_PAGE => 20;
use constant UPLOAD_LIMIT => 10 * 1024 * 1024; # 10mb

sub connect_db() {
    my $host     = $ENV{ISUCONP_DB_HOST}     || 'localhost';
    my $port     = $ENV{ISUCONP_DB_PORT}     || '3306';
    my $user     = $ENV{ISUCONP_DB_USER}     || 'root';
    my $password = $ENV{ISUCONP_DB_PASSWORD} || '';
    my $dbname   = $ENV{ISUCONP_DB_NAME}     || 'isuconp';

    my $dsn = "dbi:mysql:database=$dbname;host=$host;port=$port";
    my $dbh = DBIx::Sunny->connect($dsn, $user, $password, {
        mysql_enable_utf8mb4 => 1,
        mysql_auto_reconnect => 1,
    });
    return $dbh;
}

sub dbh($self) {
    $self->{_dbh} //= connect_db();
}

sub db_initialize($self) {
    my $sqls = [
        "DELETE FROM users WHERE id > 1000",
        "DELETE FROM posts WHERE id > 10000",
        "DELETE FROM comments WHERE id > 100000",
        "UPDATE users SET del_flg = 0",
        "UPDATE users SET del_flg = 1 WHERE id % 50 = 0",
    ];

    for my $sql ($sqls->@*) {
        $self->dbh->query($sql);
    }
}

sub try_login($self, $account_name, $password) {
    my $user = $self->dbh->select_row(
        'SELECT * FROM users WHERE account_name = ? AND del_flg = 0',
        $account_name,
    );

    if (caluculate_password_hash($user->{account_name}, $password) eq $user->{passhash}) {
        return $user;
    } else {
        return undef;
    }
}

sub validate_user($account_name, $password) {
    return $account_name =~ /\A[0-9a-zA-Z_]{3,}\z/ &&
        $password =~ /\A[0-9a-zA-Z_]{6,}\z/;
}

sub digest($src) {
    # opensslのバージョンによっては (stdin)= というのがつくので取る
    my $escaped_src = shell_quote($src);
    my $out = `printf "%s" $escaped_src | openssl dgst -sha512 | sed 's/^.*= //'`;
    if ($? != 0) {
        infof("digest failed: %s", $src);
        return "";
    }

    chomp($out);
    return $out;
}

sub caluculate_salt($account_name) {
    return digest($account_name);
}

sub caluculate_password_hash($account_name, $password) {
    return digest($password . ":" . caluculate_salt($account_name));
}

sub get_session_user($self, $c) {
    my $session = Plack::Session->new($c->env);

    my $uid = $session->get('user_id');
    unless (defined $uid) {
        return undef;
    }

    my $user = $self->dbh->select_row('SELECT * FROM `users` WHERE `id` = ?', $uid);
    return $user;
}

sub get_flash($self, $c, $key) {
    my $session = Plack::Session->new($c->env);

    my $flash = $session->get($key);
    unless (defined $flash) {
        return undef;
    }

    $session->remove($key);
    return $flash;
}

# $results: ArrayRef[Post]
# $csrf_token: Str
# $all_comments: Bool
sub make_posts($self, $results, $csrf_token, $all_comments) {
    my $posts = [];

    for my $p ($results->@*) {
        my $comment_count = $self->dbh->select_one(
            'SELECT COUNT(*) AS `count` FROM `comments` WHERE `post_id` = ?',
            $p->{id},
        );
        $p->{comment_count} = $comment_count;

        my $query = 'SELECT * FROM `comments` WHERE `post_id` = ? ORDER BY `created_at` DESC';
        if (!$all_comments) {
            $query .= ' LIMIT 3';
        }
        my $comments = $self->dbh->select_all($query, $p->{id});

        for (my $i = 0; $i < $comments->@*; $i++) {
            my $comment_user = $self->dbh->select_row(
                'SELECT * FROM `users` WHERE `id` = ?',
                $comments->[$i]->{user_id},
            );
            $comments->[$i]->{user} = $comment_user;
        }
        $p->{comments} = [ reverse($comments->@*) ];

        my $user = $self->dbh->select_row(
            'SELECT * FROM `users` WHERE `id` = ?',
            $p->{user_id},
        );
        $p->{user} = $user;

        $p->{csrf_token} = $csrf_token;

        if ($p->{user}->{del_flg} == 0) {
            push $posts->@*, $p;
        }

        if (scalar($posts->@*) >= POSTS_PER_PAGE) {
            last;
        }
    }

    return $posts;
}

sub image_url($post) {
    my $ext = "";
    if ($post->{mime} eq 'image/jpeg') {
        $ext = 'j.pg';
    } elsif ($post->{mime} eq 'image/png') {
        $ext = '.png';
    } elsif ($post->{mime} eq 'image/gif') {
        $ext = '.gif';
    }
    return "/image/" . $post->{id} . $ext;
}

sub is_login($user) {
    return defined $user;
}

sub get_csrf_token($self, $c) {
    my $session = Plack::Session->new($c->env);
    my $csrf_token = $session->get('csrf_token');
    unless (defined $csrf_token) {
        return "";
    }
    return $csrf_token;
}

sub secure_random_str($b) {
    my $rand = Crypt::URandom::urandom($b);
    return unpack("H*", $rand);
}



sub get_initialize($self, $c) {
    $self->db_initialize();

    $c->halt_no_content(HTTP_OK);
}

sub get_login($self, $c) {
    my $me = $self->get_session_user($c);
    if (is_login($me)) {
        return $c->redirect('/');
    }

    $c->render('login.tx', {
        me    => $me,
        flash => $self->get_flash($c, 'notice'),
    });
}

sub post_login($self, $c) {
    if (is_login($self->get_session_user($c))) {
        return $c->redirect('/');
    }

    my $u = $self->try_login($c->req->parameters->{account_name}, $c->req->parameters->{password});
    if ($u) {
        my $session = Plack::Session->new($c->env);
        $session->set('user_id', $u->{id});
        $session->set('csrf_token', secure_random_str(16));

        return $c->redirect('/');
    }
    else {
        my $session = Plack::Session->new($c->env);
        $session->set('notice', 'アカウント名かパスワードが間違っています');

        return $c->redirect('/login');
    }
}

sub get_register($self, $c) {
    if (is_login($self->get_session_user($c))) {
        return $c->redirect('/');
    }

    return $c->render('register.tx', {
        flash => $self->get_flash($c, 'notice'),
    });
}

sub post_register($self, $c) {
    if (is_login($self->get_session_user($c))) {
        return $c->redirect('/');
    }

    my $account_name = $c->req->parameters->{account_name};
    my $password     = $c->req->parameters->{password};

    if (!validate_user($account_name, $password)) {
        my $session = Plack::Session->new($c->env);
        $session->set('notice', 'アカウント名は3文字以上、パスワードは6文字以上である必要があります');

        return $c->redirect('/register');
    }

    my $exists = $self->dbh->select_one(
        'SELECT 1 FROM users WHERE `account_name` = ?',
        $account_name,
    );
    if ($exists) {
        my $session = Plack::Session->new($c->env);
        $session->set('notice', 'アカウント名がすでに使われています');

        return $c->redirect('/register');
    }

    my $query = 'INSERT INTO `users` (`account_name`, `passhash`) VALUES (?,?)';
    my $result = $self->dbh->query(
        $query,
        $account_name,
        caluculate_password_hash($account_name, $password),
    );

    my $uid = $self->dbh->last_insert_id;

    my $session = Plack::Session->new($c->env);
    $session->set('user_id', $uid);
    $session->set('csrf_token', secure_random_str(16));

    return $c->redirect('/');
}

sub get_logout($self, $c) {
    my $session = Plack::Session->new($c->env);
    $session->remove('user_id');

    return $c->redirect('/');
}

sub get_index($self, $c) {
    my $me = $self->get_session_user($c);

    my $results = $self->dbh->select_all(
        'SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` ORDER BY `created_at` DESC',
    );

    my $posts = $self->make_posts($results, $self->get_csrf_token($c), 0);

    $c->render('index.tx', {
        posts      => $posts,
        me         => $me,
        csrf_token => $self->get_csrf_token($c),
        flash      => $self->get_flash($c, 'notice'),
    });
}

sub get_account_name($self, $c) {
    my $account_name = $c->args->{account_name};
    my $user = $self->dbh->select_row(
        'SELECT * FROM `users` WHERE `account_name` = ? AND `del_flg` = 0',
        $account_name,
    );
    unless ($user) {
        $c->halt(HTTP_NOT_FOUND);
    }

    my $results = $self->dbh->select_all(
        'SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `user_id` = ? ORDER BY `created_at` DESC',
        $user->{id},
    );

    my $posts = $self->make_posts($results, $self->get_csrf_token($c), 0);

    my $comment_count = $self->dbh->select_one(
        'SELECT COUNT(*) AS `count` FROM `comments` WHERE `user_id` = ?',
        $user->{id},
    );

    my $post_ids = $self->dbh->select_all(
        'SELECT `id` FROM `posts` WHERE `user_id` = ?',
        $user->{id},
    );
    my $post_count = scalar($post_ids->@*);

    my $commented_count = 0;
    if ($post_count > 0) {
        $commented_count = $self->dbh->select_one(
            'SELECT COUNT(*) AS `count` FROM `comments` WHERE `post_id` IN (?)',
            $post_ids,
        );
    }

    my $me = $self->get_session_user($c);

    return $c->render('user.tx', {
        posts           => $posts,
        user            => $user,
        post_count      => $post_count,
        comment_count   => $comment_count,
        commented_count => $commented_count,
        me              => $me,
        csrf_token      => $self->get_csrf_token($c),
    });
}

sub get_posts($self, $c) {
    my $max_created_at = $c->req->parameters->{max_created_at};
    if (!$max_created_at) {
        return $c->halt(HTTP_NOT_FOUND);
    }

    my $results = $self->dbh->select_all(
        'SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `created_at` <= ? ORDER BY `created_at` DESC',
        $max_created_at,
    );

    my $posts = $self->make_posts($results, $self->get_csrf_token($c), 0);

    if (scalar($posts->@*) == 0) {
        return $c->halt(HTTP_NOT_FOUND);
    }

    $c->render('posts.tx', {
        posts      => $posts,
        me         => $self->get_session_user($c),
    });
}

sub get_post_id($self, $c) {
    my $pid = $c->args->{id};

    my $results = $self->dbh->select_all('SELECT * FROM `posts` WHERE `id` = ?', $pid);

    my $posts = $self->make_posts($results, $self->get_csrf_token($c), 1);
    if (scalar($posts->@*) == 0) {
        $c->halt(HTTP_NOT_FOUND);
    }

    my $post = $posts->[0];
    my $me = $self->get_session_user($c);

    return $c->render('post_id.tx', {
        post       => $post,
        me         => $me,
        csrf_token => $self->get_csrf_token($c),
    });
}

sub post_index($self, $c) {
    my $me = $self->get_session_user($c);
    if (!is_login($me)) {
        return $c->redirect('/login');
    }

    if ($c->req->parameters->{csrf_token} ne $self->get_csrf_token($c)) {
        return $c->halt(HTTP_UNPROCESSABLE_ENTITY);
    }

    my $file = $c->req->uploads->{file};
    unless ($file) {
        my $session = Plack::Session->new($c->env);
        $session->set('notice', '画像が必須です');

        return $c->redirect('/');
    }

    my $mime = "";
    if ($file) {
        # 投稿のContent-Typeからファイルのタイプを決定する
        my $content_type = $file->content_type;
        if ($content_type =~ /jpeg/) {
            $mime = "image/jpeg";
        } elsif ($content_type =~ /png/) {
            $mime = "image/png";
        } elsif ($content_type =~ /gif/) {
            $mime = "image/gif";
        } else {
            my $session = Plack::Session->new($c->env);
            $session->set('notice', '投稿できる画像形式はjpgとpngとgifだけです');

            return $c->redirect('/');
        }
    }

    my $filedata = do {
        open my $fh, '<', $file->path or die $!;
        local $/;
        <$fh>;
    };

    if (length($filedata) > UPLOAD_LIMIT) {
        my $session = Plack::Session->new($c->env);
        $session->set('notice', 'ファイルサイズが大きすぎます');

        return $c->redirect('/');
    }

    my $query = "INSERT INTO `posts` (`user_id`, `mime`, `imgdata`, `body`) VALUES (?,?,?,?)";
    my $result = $self->dbh->query(
        $query,
        $me->{id},
        $mime,
        $filedata,
        $c->req->parameters->{body},
    );

    my $pid = $self->dbh->last_insert_id;

    return $c->redirect('/posts/' . $pid);

}

sub get_image($self, $c) {
    my $pid = $c->args->{id};

    my $post = $self->dbh->select_row('SELECT * FROM `posts` WHERE `id` = ?', $pid);
    if (!$post) {
        return $c->halt(HTTP_NOT_FOUND);
    }

    my $ext = $c->args->{ext};
    if ($ext eq 'jpg' && $post->{mime} eq 'image/jpeg' ||
        $ext eq 'png' && $post->{mime} eq 'image/png' ||
        $ext eq 'gif' && $post->{mime} eq 'image/gif') {
        $c->res->content_type($post->{mime});
        $c->res->body($post->{imgdata});
        return $c->res;
    }

    return $c->halt(HTTP_NOT_FOUND);
}

sub post_comment($self, $c) {
    my $me = $self->get_session_user($c);
    if (!is_login($me)) {
        return $c->redirect('/login');
    }

    if ($c->req->parameters->{csrf_token} ne $self->get_csrf_token($c)) {
        return $c->halt(HTTP_UNPROCESSABLE_ENTITY);
    }

    my $post_id = $c->req->parameters->{post_id};

    my $query = "INSERT INTO `comments` (`post_id`, `user_id`, `comment`) VALUES (?,?,?)";
    my $result = $self->dbh->query(
        $query,
        $post_id,
        $me->{id},
        $c->req->parameters->{comment},
    );

    return $c->redirect('/posts/' . $post_id);
}

sub get_admin_banned($self, $c) {
    my $me = $self->get_session_user($c);
    if (!is_login($me)) {
        return $c->redirect('/login');
    }

    if ($me->{authority} == 0) {
        return $c->halt_no_content(HTTP_FORBIDDEN);
    }


    my $users = $self->dbh->select_all(
        'SELECT * FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC',
    );

    $c->render('banned.tx', {
        users => $users,
        me    => $me,
        csrf_token => $self->get_csrf_token($c),
    });
}

sub post_admin_banned($self, $c) {
    my $me = $self->get_session_user($c);
    if (!is_login($me)) {
        return $c->redirect('/login');
    }

    if ($me->{authority} == 0) {
        return $c->halt_no_content(HTTP_FORBIDDEN);
    }

    if ($c->req->parameters->{csrf_token} ne $self->get_csrf_token($c)) {
        return $c->halt(HTTP_UNPROCESSABLE_ENTITY);
    }

    my $query = "UPDATE `users` SET `del_flg` = ? WHERE `id` = ?";

    for my $id ($c->req->parameters->get_all('uid[]')) {
        $self->dbh->query($query, 1, $id);
    }

    return $c->redirect('/admin/banned');
}

sub static_file($self, $c) {
    $self->{_file} //= Plack::App::File->new({ root => $self->root_dir . '/../public' });
    $self->{_file}->call($c->req->env);
};

{
    # override default_functions to add image_url
    no warnings qw(once);
    *Text::Xslate::default_functions = sub {
        return {
            image_url => \&image_url,
        };
    };
}

get '/initialize'                => \&get_initialize;
get '/login'                     => \&get_login;
post '/login'                    => \&post_login;
get '/register'                  => \&get_register;
post '/register'                 => \&post_register;
get '/logout'                    => \&get_logout;
get '/'                          => \&get_index;
get '/posts'                     => \&get_posts;
get '/posts/{id}'                => \&get_post_id;
post '/'                         => \&post_index;
get '/image/{id}.{ext}'          => \&get_image;
post '/comment'                  => \&post_comment;
get '/admin/banned'              => \&get_admin_banned;
post '/admin/banned'             => \&post_admin_banned;
get '/@{account_name:[a-zA-Z]+}' => \&get_account_name;
get '/*'                         => \&static_file;

