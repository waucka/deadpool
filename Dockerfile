FROM debian:latest

MAINTAINER Alex Wauck "alexwauck@exosite.com"
EXPOSE 5000

ENV GIN_MODE release

RUN apt-get update && apt-get upgrade -y && apt-get -y install curl

COPY build/linux-amd64/deadpool /usr/bin/deadpool
RUN chmod 0755 /usr/bin/deadpool

CMD ["/usr/bin/deadpool", "--config", "/etc/deadpool/deadpool.yaml"]
