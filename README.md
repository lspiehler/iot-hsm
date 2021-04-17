# IoT-HSM
IoT-HSM allows Yubikeys and SoftHSM2 devices to be managed and serve as an "IoT HSM" interface for signing operations from PKIaaS.io.

## Install IoT-HSM on Ubuntu 20.04
The following commands should be run as root on a base install of Ubuntu 20.04. You can switch to the root user using the "su" command or "sudo su -"
```
apt update
apt -y install curl
curl -sL https://raw.githubusercontent.com/lspiehler/iot-hsm/master/scripts/setup_ubuntu2004.sh | bash -
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
docker run -it -d --restart=always --name iot-hsm -p 3001:3000 -v iot-hsm:/var/lib/softhsm/tokens lspiehler/iot-hsm:latest
```

## Snap Build
```
apt install -y snapd
snap install snapcraft --classic
snapcraft
```