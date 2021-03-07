# IoT-HSM
IoT-HSM allows Yubikeys and SoftHSM2 devices to be managed and serve as an "IoT HSM" interface for signing operations from PKIaaS.io.

## Install dependencies
Example below is for Ubuntu 20.04
```
curl -sL https://deb.nodesource.com/setup_14.x -o nodesource_setup.sh
bash nodesource_setup.sh
apt update
apt -y install openssl opensc libengine-pkcs11-openssl ykcs11 softhsm2 nodejs
```

## Set timezone to UTC
```
timedatectl set-timezone UTC
```

## Install IoT-HSM
```
git clone https://github.com/lspiehler/iot-hsm.git
cd iot-hsm
npm install
```

## Docker Command
```
docker run -it -d --restart=always --name iot-hsm -p 3001:3000 -v iot-hsm:/var/lib/softhsm/tokens lspiehler/iot-hsm:latest
```