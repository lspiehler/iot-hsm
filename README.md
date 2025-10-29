# IoT-HSM
IoT-HSM allows Yubikeys and SoftHSM2 devices to be managed and serve as an "IoT HSM" interface for signing operations from [PKIaaS.io](https://www.pkiaas.io/iot-hsm).

## Install IoT-HSM on Ubuntu 25.10
The following commands should be run as root on a base install of [Ubuntu 25.10](https://ubuntu.com/download/server). You can switch to the root user using the "su" command or "sudo su -"
```
apt update
apt -y install curl
curl -sL https://raw.githubusercontent.com/lspiehler/iot-hsm/master/scripts/setup_ubuntu2510.sh | bash -
```

You should now be able to login and begin managing your HSM by navigating to https://youripaddress

The password for the web interface can be changed by running the following command from a terminal as root or by prefixing the command with "sudo": 
```
htpasswd /etc/apache2/.htpasswd admin
```

The certificates for this appliance can be replaced by updating /etc/ssl/certs/iothsm.pem with your signed certificate and /etc/ssl/private/iothsm.key with your private key and reloading apache with the following command from a terminal as root or by prefixing the command with "sudo":
```
systemctl reload apache2
```

## Docker Command
```
docker run -it -d --restart=always --name iot-hsm -e LISTENIP=0.0.0.0 -p 3001:3000 -v iot-hsm:/var/lib/softhsm/tokens lspiehler/iot-hsm:latest
```

## Snap Build
```
apt install -y snapd
snap install snapcraft --classic
snapcraft
```

### Troubleshooting
Uninstall dependencies
```
apt remove opensc pkcs11-provider ykcs11 softhsm2 yubico-piv-tool
apt autoremove
```
Reinstall dependencies
```
apt install opensc pkcs11-provider ykcs11 softhsm2 yubico-piv-tool
```
Run manually, specifying environment variables
```
LISTENIP=0.0.0.0 PORT=3001 PLATFORMFQDN=pkiaas.io node bin/www
```

```
pkcs11-tool --show-info --module /usr/lib/x86_64-linux-gnu/libykcs11.so
pkcs11-tool --list-slots --module /usr/lib/x86_64-linux-gnu/libykcs11.so
pkcs11-tool --list-objects --module /usr/lib/x86_64-linux-gnu/libykcs11.so --slot 0
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/libykcs11.so --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --slot 0x0 --id 13 --delete-object --type privkey
```
