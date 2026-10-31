# IoT-HSM
IoT-HSM allows Yubikeys and SoftHSM2 devices to be managed and serve as an "IoT HSM" interface for signing operations from [PKIaaS.io](https://www.pkiaas.io/iot-hsm).

## Install IoT-HSM on Ubuntu 24.04 or 25.10
The following commands should be run as root on a base install of Ubuntu 24.04 or Ubuntu 25.10. You can switch to the root user using the "su" command or "sudo su -"
```
apt update
apt -y install curl
curl -sL https://raw.githubusercontent.com/lspiehler/iot-hsm/master/scripts/setup_ubuntu.sh | bash -
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
The web interface has no authentication of its own and can use every key on the HSM. Only expose it through a reverse proxy that requires a login and HTTPS, like the Apache configuration created by the Ubuntu install above. The command below publishes it on 127.0.0.1 only.
```
docker run -it -d --restart=always --name iot-hsm -e LISTENIP=0.0.0.0 -p 127.0.0.1:3001:3000 -v iot-hsm:/var/lib/softhsm/tokens -v /var/node/iot-hsm/state:/var/node/iot-hsm/state ghcr.io/lspiehler/iot-hsm:latest
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
- Ubuntu install (pm2): as the `iothsm` user in `/var/node/iot-hsm`, run `git fetch --tags && git checkout v1.0.0`, then `npm ci --ignore-scripts` (dependencies can change between versions; the only install script, in the unused `zlib` package, is not needed), then `pm2 restart iot-hsm`.
- Docker: pull the new image and recreate the container with the same volumes and settings.

PKIaaS.io reads the latest release of this repository to tell HSM owners when an update is available. Pre-releases (for example `v1.1.0-rc.1`, published with `--prerelease`) are ignored, so use them for testing.

The agent tells the platform its version, commit and library versions, its capabilities and its token type in its signed replies (`lib/agentInfo.js`). These fields never contain PINs, keys, paths, channel IDs, token serial numbers or the hostname.

## A wrong PIN
A YubiKey blocks its PIN after a few wrong tries, so the agent stops using a token as soon as a login with its PIN fails, whether for a signature or for a channel certificate renewal. Until then it doesn't offer to sign for that token's CAs: when its channel certificate is current it replies that it is busy, with the PIN state `rejected`. After correcting the PIN, reload the slots (`/api/reload`) or restart the agent.

## Tests
```
npm test
```
