#!/bin/bash

#Update apt
apt update

#Install curl
apt -y install curl

#Install node repos
curl -sL https://deb.nodesource.com/setup_22.x | bash -

#Install all required software
apt -y install sysvbanner openssl pkcs11-provider softhsm2 nodejs git apache2 apache2-utils

apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 32CBA1A9

add-apt-repository -y ppa:yubico/stable

apt -y install opensc ykcs11 yubico-piv-tool

#Time zone must be set to UTC!
timedatectl set-timezone UTC

#Create iothsm user and add to necessary groups
useradd -m iothsm
usermod -s /bin/bash -a -G softhsm iothsm

#allow iothsm user access to "smartcards"
cat << EOF > /usr/share/polkit-1/rules.d/sssd-pcsc.rules
polkit.addRule(function(action, subject) {
    if (action.id == "org.debian.pcsc-lite.access_card" &&
        subject.user == "iothsm") {
            return polkit.Result.YES;
    }
});

polkit.addRule(function(action, subject) {
    if (action.id == "org.debian.pcsc-lite.access_pcsc" &&
        subject.user == "iothsm") {
            return polkit.Result.YES;
    }
});
EOF

systemctl restart polkit

#Create directory and set ownership
mkdir /var/node
chown iothsm:iothsm /var/node
cd /var/node

#Clone git repo and change working dir
sudo -u iothsm git clone https://github.com/lspiehler/iot-hsm.git
cd iot-hsm

#Install node dependencies
sudo -u iothsm npm install

#Install pm2 to run service as a daemon
npm install pm2 -g

#Run pm2 st startup
pm2 startup ubuntu -u iothsm --hp /home/iothsm

#Configure service to listen only on localhost
cd /var/node/iot-hsm
cat << EOF > .env
LISTENIP=localhost
EOF

#Start service with PM2 and save
sudo -u iothsm pm2 start ./bin/www --name="iot-hsm"
sudo -u iothsm pm2 save

#Disable the default Apache site
a2dissite 000-default.conf

#Create the log directory for the new Apache config
mkdir /var/log/apache2/iothsm

#Generate a new private key and configure privileges
openssl genpkey -outform PEM -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /etc/ssl/private/iothsm.key
chmod 640 /etc/ssl/private/iothsm.key
chown root:ssl-cert /etc/ssl/private/iothsm.key

#Create OpenSSL config
cat << EOF > /tmp/openssl-iothsm.cnf
[ req ]
default_md = sha256
prompt = no
req_extensions = req_ext
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
commonName = PKIaaS.io IoT-HSM
countryName = US
[ req_ext ]
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=critical,serverAuth,clientAuth
EOF

#Create iothsm CSR
openssl req -new -nodes -key /etc/ssl/private/iothsm.key -config /tmp/openssl-iothsm.cnf -nameopt utf8 -utf8 -out /tmp/iothsm.csr

#Add params to OpenSSL config
cat << EOF >> /tmp/openssl-iothsm.cnf
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF

#Self-Sign iothsm CSR
openssl req -x509 -nodes -in /tmp/iothsm.csr -days 3650 -key /etc/ssl/private/iothsm.key -config /tmp/openssl-iothsm.cnf -extensions req_ext -nameopt utf8 -utf8 -out /etc/ssl/certs/iothsm.pem
chmod 644 /etc/ssl/certs/iothsm.pem

#Create the Apache config
cat << EOF > /etc/apache2/sites-available/iot-hsm.conf
<Virtualhost *:80>
        RewriteEngine On
        RewriteCond %{HTTPS} off
        RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
        ErrorLog /var/log/apache2/iothsm/error.log
        CustomLog /var/log/apache2/iothsm/access.log common
</VirtualHost>

<VirtualHost *:443>
        Header always set Strict-Transport-Security "max-age=63072000; preload"
        SSLEngine On
        #SSLProtocol all -SSLv2 -SSLv3 -TLSv1
        SSLProtocol all -SSLv2 -SSLv3
        SSLHonorCipherOrder on
        SSLCipherSuite ALL:!aNULL:!eNULL:!LOW:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS:!RC4:!IDEA-CBC-SHA
        SSLCertificateFile /etc/ssl/certs/iothsm.pem
        SSLCertificateKeyFile /etc/ssl/private/iothsm.key
        SSLProxyEngine on
        SSLProxyCheckPeerCN Off
        SSLProxyCheckPeerName Off
        ProxyPreserveHost On
        UseCanonicalName On
        KeepAlive On

        <proxy balancer://iothsm>
                BalancerMember http://127.0.0.1:3000
        </proxy>

        <Location />
                AuthType Basic
                AuthName "Restricted Content"
                AuthUserFile /etc/apache2/.htpasswd
                Require valid-user
                ProxyPass "balancer://iothsm/"
                ProxyPassReverse "balancer://iothsm"
        </Location>

        ErrorLog /var/log/apache2/iothsm/error.log
        CustomLog /var/log/apache2/iothsm/access.log common
</VirtualHost>
EOF

#Enable new Apache config
a2ensite iot-hsm.conf

#Enable necessary Apache modules
a2enmod rewrite headers proxy proxy_balancer lbmethod_byrequests proxy_http proxy_ajp ssl

#Restart Apache
systemctl restart apache2

#Open necessary firewall ports
ufw allow 'Apache'

#Create default admin user if .htpasswd doesn't exist
if [ ! -f "/etc/apache2/.htpasswd" ]; then
    htpasswd -b -c /etc/apache2/.htpasswd admin admin
fi

#Set recommended permissions and ownership for .htpasswd file
chown www-data:www-data /etc/apache2/.htpasswd
chmod 640 /etc/apache2/.htpasswd

#If default admin password is set to default, prompt to change it
htpasswd -vb /etc/apache2/.htpasswd admin admin 2> /dev/null && echo "Enter a new password for the admin user" && htpasswd /etc/apache2/.htpasswd admin

#Show banner
banner IoT-HSM
echo "You've successfully installed IoT-HSM"
echo 
echo "The certificates for this appliance can be replaced by updating /etc/ssl/certs/iothsm.pem and /etc/ssl/private/iothsm.key and reloading apache with the command \"systemctl reload apache2\""
echo
echo "The password for the web interface can be changed by running the command \"htpasswd /etc/apache2/.htpasswd admin\""
echo
echo -e "You should now be able to login and begin managing your HSM by navigating to \e[32mhttps://<your ip>\e[0m"
