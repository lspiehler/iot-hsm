# IoT-HSM
IoT-HSM allows Yubikeys and SoftHSM2 devices to be managed and serve as an "IoT HSM" interface for signing operations from PKIaaS.io.

## Install dependencies
Example below is for Ubuntu 20.04
```
apt update
apt -y install curl
curl -sL https://deb.nodesource.com/setup_14.x | bash -
apt update
apt -y install openssl opensc libengine-pkcs11-openssl ykcs11 softhsm2 nodejs git yubico-piv-tool
```

## Set timezone to UTC
```
timedatectl set-timezone UTC
```

## Create User and Install IoT-HSM
```
useradd -m iothsm
usermod -s /bin/bash -a -G softhsm iothsm
mkdir /var/node
chown iothsm:iothsm /var/node
su iothsm
cd /var/node
git clone https://github.com/lspiehler/iot-hsm.git
cd iot-hsm
npm install
```

## Start the Service
```
cd /var/node/iot-hsm
npm start
```

Finally, navigate to http://YOUR-IP:3000

## Start the Service at Boot
Run the below commands as root
```
npm install pm2 -g
pm2 startup ubuntu -u iothsm --hp /home/iothsm
su iothsm
cd /var/node/iothsm
pm2 start ./bin/www --name="iot-hsm"
pm2 save
```

The commands below are for alternative builds and can be ignored.

## Docker Command
```
docker run -it -d --restart=always --name iot-hsm -p 3001:3000 -v iot-hsm:/var/lib/softhsm/tokens lspiehler/iot-hsm:latest
```

## Snap Build
```
apt install -y snapd
snap install snapcraft --classic
snapcraft
```