FROM docker.io/ubuntu:focal
LABEL maintainer Lyas Spiehler

ENV DEBIAN_FRONTEND=noninteractive

ENV TZ=UTC

RUN apt update

RUN apt install -y openssl git curl wget yubico-piv-tool pcscd opensc libengine-pkcs11-openssl ykcs11 softhsm2

RUN curl -sL https://deb.nodesource.com/setup_14.x | bash -

RUN apt update

RUN apt install -y nodejs

RUN mkdir -p /var/node/iot-hsm

ADD . /var/node/iot-hsm/

WORKDIR /var/node/iot-hsm

RUN npm install

EXPOSE 3000/tcp

CMD ["node", "bin/www"]
