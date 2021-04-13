#!/bin/bash

apt update
apt -y install openssl opensc libengine-pkcs11-openssl ykcs11 softhsm2 nodejs git yubico-piv-tool

timedatectl set-timezone UTC

useradd -m iothsm
usermod -s /bin/bash -a -G softhsm iothsm
mkdir /var/node
chown iothsm:iothsm /var/node
su iothsm
cd /var/node
sudo -u iothsm git clone https://github.com/lspiehler/iot-hsm.git
cd iot-hsm
sudo -u iothsm npm install
npm install pm2 -g
pm2 startup ubuntu -u iothsm --hp /home/iothsm
cd /var/node/iothsm
sudo -u iothsm pm2 start ./bin/www --name="iot-hsm"
sudo -u iothsm pm2 save