FROM perl:5.38

WORKDIR /tmp
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get install -y curl wget gcc g++ make sqlite3 && \
    wget -q https://dev.mysql.com/get/mysql-apt-config_0.8.29-1_all.deb && \
    apt-get -y install ./mysql-apt-config_0.8.29-1_all.deb && \
    apt-get -y update && \
    apt-get -y install default-mysql-client

RUN mkdir -p /home/webapp
WORKDIR /home/webapp

COPY cpanfile ./
RUN cpm install --show-build-log-on-failure
COPY . .

ENV PERL5LIB=/home/webapp/local/lib/perl5
ENV PATH=/home/webapp/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

CMD ["./local/bin/plackup", "app.psgi"]
