use v5.38;

use FindBin;
use lib "$FindBin::Bin/lib";

use File::Basename;
use Plack::Builder;
use Plack::Loader;
use Cache::Memcached::Fast::Safe;
use Plack::Session::Store::Cache;

use Isuconp;

my $root_dir = File::Basename::dirname(__FILE__);

my $app = builder {
    enable 'ReverseProxy';
    enable 'AccessLog';
    enable 'Session::Cookie',
        session_key => 'isuconp-perl',
        path     => '/',
        httponly => 1,
        secret      => $ENV{ISUCONP_SESSION_SECRET} || 'setagaya',

        store => Plack::Session::Store::Cache->new(
            cache => Cache::Memcached::Fast::Safe->new(
                {
                    servers => [ { address => $ENV{ISUCONP_MEMCACHED_ADDRESS} || 'localhost:11211' } ],
                    namespace => 'iscogram_',
                    utf8 => 1,
                }
            )
        );
    Isuconp->psgi($root_dir);
};

my $loader = Plack::Loader->load(
    'Starlet',
    max_worker => 5,
    port => 8080,
);
$loader->run($app);
