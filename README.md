# IoT-HSM
IoT-HSM allows Yubikeys and SoftHSM2 devices to be managed and serve as an "IoT HSM" interface for signing operations from [PKIaaS.io](https://www.pkiaas.io/iot-hsm).

## Install IoT-HSM on Ubuntu 24.04 or 26.04
The following commands should be run as root on a base install of Ubuntu 24.04 or Ubuntu 26.04. You can switch to the root user using the "su" command or "sudo su -"
```
apt update
apt -y install curl
curl -sL https://raw.githubusercontent.com/lspiehler/iot-hsm/master/scripts/setup_ubuntu.sh | bash -
```

The script installs the latest release of IoT-HSM (the one shown at https://github.com/lspiehler/iot-hsm/releases/latest), not the newest code on `master`. If it can't look the release up, it stops before installing IoT-HSM.

The script turns on the firewall (ufw) if it is off. It first allows the TCP ports that sshd listens on, so that turning the firewall on doesn't cut off SSH, then ports 80 and 443 for the web interface (80 only redirects to HTTPS), and then turns ufw on. If ufw is already on, the script leaves its SSH rules as they are and only allows ports 80 and 443. If ufw is off and the script finds no port that sshd listens on, it adds the rules for ports 80 and 443 but leaves ufw off and prints how to turn it on. If you move SSH to another port later, allow the new port in ufw first, for example `ufw allow 2222/tcp`.

Once IoT-HSM is installed, the script asks for a name for the appliance, which the platform shows instead of the appliance's ID. Press Enter to use the hostname (offered only when it is a valid name). Without a terminal, for example in automation, the appliance gets no name unless you set it before running the script: `curl -sL ... | AGENT_NAME="Rack 4 HSM" bash -` (`AGENT_NAME=` sends no name). Run that as root rather than through `sudo`, which drops `AGENT_NAME`. Run the script in the foreground: in the background it stops at the question. A name is 1 to 64 letters, digits, spaces and `. _ - ( ) # : / @`; one the platform wouldn't accept is not saved. The name is saved in `/var/node/iot-hsm/.env`; to change it later, edit `AGENT_NAME` there and run `sudo -u iothsm pm2 restart iot-hsm`.

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
The web interface has no authentication of its own and can use every key on the HSM. Only expose it through a reverse proxy that requires a login and HTTPS, like the Apache configuration created by the Ubuntu install above. The command below publishes it on 127.0.0.1 only.
```
docker run -it -d --restart=always --name iot-hsm -e LISTENIP=0.0.0.0 -p 127.0.0.1:3001:3000 -v iot-hsm:/var/lib/softhsm/tokens -v /var/node/iot-hsm/state:/var/node/iot-hsm/state ghcr.io/lspiehler/iot-hsm:latest
```
To name the appliance, add `-e AGENT_NAME="Rack 4 HSM"` with your own name. `AGENT_NAME` is the name the platform shows for the appliance instead of its ID: 1 to 64 letters, digits, spaces and `. _ - ( ) # : / @`. A container's hostname is a random ID, so the agent never sends it; without `AGENT_NAME` the platform shows the ID.

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
Run manually, specifying environment variables (LISTENIP=0.0.0.0 makes the unauthenticated web interface reachable from the network)
```
LISTENIP=127.0.0.1 PORT=3001 PLATFORMFQDN=pkiaas.io node bin/www
```

```
pkcs11-tool --show-info --module /usr/lib/x86_64-linux-gnu/libykcs11.so
pkcs11-tool --list-slots --module /usr/lib/x86_64-linux-gnu/libykcs11.so
pkcs11-tool --list-objects --module /usr/lib/x86_64-linux-gnu/libykcs11.so --slot 0
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/libykcs11.so --login --login-type so --so-pin 010203040506070801020304050607080102030405060708 --slot 0x0 --id 13 --delete-object --type privkey
```

## Versions and releases
The agent's version is in `package.json` and follows [semantic versioning](https://semver.org). Agents update on their own schedule, so every version must keep working with the current platform and with older platforms.
- Patch (1.0.1): fixes.
- Minor (1.1.0): new features, settings or offer fields that older platforms can ignore.
- Major (2.0.0): only with a platform that already supports the change, since it can stop older platforms from using the agent.

Raise the version in the pull request that changes the agent (`npm version <version> --no-git-tag-version` updates `package.json` and `package-lock.json`). After the merge, tag the merge commit and publish a GitHub release with its notes:
```
git tag -a v1.0.0 -m "IoT-HSM 1.0.0" <merge commit>
git push origin v1.0.0
gh release create v1.0.0 --verify-tag --title "IoT-HSM 1.0.0" --generate-notes
```
To update an installed agent to a release:
- Ubuntu install (pm2): as the `iothsm` user in `/var/node/iot-hsm`, run `git fetch --tags && git checkout v1.0.0`, then `npm ci --ignore-scripts` (dependencies can change between versions; their install scripts, a build in the unused `zlib` package and a version warning in `protobufjs`, are not needed), then `pm2 restart iot-hsm`.
- Docker: pull the new image and recreate the container with the same volumes and settings.

PKIaaS.io reads the latest release of this repository to tell HSM owners when an update is available. Pre-releases (for example `v1.1.0-rc.1`, published with `--prerelease`) are ignored, so use them for testing.

The agent tells the platform its version, commit and library versions, its capabilities and its token type in its signed replies (`lib/agentInfo.js`). These fields never contain PINs, keys, paths, channel IDs or token serial numbers. The only name they carry is the one the owner gave the appliance (`AGENT_NAME`), which may be its hostname if the owner chose it at the installer's question; the agent never sends the hostname on its own.

## A wrong PIN
A YubiKey blocks its PIN after a few wrong tries, so the agent stops using a token as soon as a login with its PIN fails, whether for a signature or for a channel certificate renewal. Until then it doesn't offer to sign for that token's CAs: when its channel certificate is current it replies that it is busy, with the PIN state `rejected`. After correcting the PIN, reload the slots (`/api/reload`) or restart the agent.

## Tests
```
npm test
```
