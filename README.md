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

## Install IoT-HSM
```
mkdir /var/node
cd /var/node
git clone https://github.com/lspiehler/iot-hsm.git
cd iot-hsm
npm install
```

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