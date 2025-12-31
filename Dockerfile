FROM docker.io/ubuntu:noble
LABEL maintainer="Lyas Spiehler"

ENV DEBIAN_FRONTEND=noninteractive
ENV NO_COLOR=1

ENV TZ=UTC

RUN apt update

RUN apt install -y curl sysvbanner openssl pkcs11-provider softhsm2 git opensc ykcs11 yubico-piv-tool gnutls-bin

RUN curl -sL https://deb.nodesource.com/setup_24.x | bash -

RUN apt update

RUN apt install -y nodejs

RUN curl -LO https://github.com/GoogleCloudPlatform/kms-integrations/releases/download/pkcs11-v1.8/libkmsp11-1.8-linux-amd64.tar.gz && tar xzf libkmsp11-*.tar.gz && mkdir -p /usr/lib/kms && mv libkmsp11-*/* /usr/lib/kms/ && chmod 755 -R /usr/lib/kms/ && chown root:root -R /usr/lib/kms/ && rm -Rf libkmsp11-*

RUN mkdir -p /var/node/iot-hsm

ADD . /var/node/iot-hsm/

WORKDIR /var/node/iot-hsm

RUN npm install

EXPOSE 3000/tcp

CMD ["node", "bin/www"]
