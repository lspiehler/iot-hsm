// Native signing (NATIVESIGNING=1): certificates are signed in-process by node-pki-signer instead of
// running openssl ca. node-pki-signer builds the same certificate as OpenSSL and falls back to OpenSSL
// (node-openssl-cert2) by itself whenever it can't sign a request natively. Off by default.
const fs = require('fs');
const crypto = require('crypto');
const { parse } = require('yaml');
const config = require('../config');
const openssl2 = require('./openssl2');

var signer = false;
var kmsClient = false;
// CA certificate → its Google KMS key version, resolved once per process
var keyVersions = {};

var enabled = function() {
    return ['1', 'true', 'yes', 'on'].indexOf(String(config.NATIVESIGNING).toLowerCase()) >= 0;
}

var getSigner = function() {
    if(!signer) {
        // loaded only when enabled: node-pki-signer needs Node 24.11 or newer
        const { createSigner } = require('node-pki-signer');
        const { KeyManagementServiceClient } = require('@google-cloud/kms');
        kmsClient = new KeyManagementServiceClient();
        signer = createSigner({
            binpath: config.opensslbinpath,
            kms: kmsClient,
            onFallback: function(fallback) {
                console.log('Native signing fell back to OpenSSL: ' + fallback.reason);
            }
        });
    }
    return signer;
}

// The CryptoKeyVersion holding the CA's key: the key is the PKCS#11 object's label in one of the key
// rings in the Google KMS module's configuration, and the version is the one with the CA certificate's
// public key. False when there is none or it can't be found, so node-pki-signer signs through the
// module with OpenSSL as before.
var getKeyVersion = function(params, callback) {
    if(params.module.split('/').at(-1) != 'libkmsp11.so') {
        callback(false);
    } else if(keyVersions.hasOwnProperty(params.publiccert)) {
        callback(keyVersions[params.publiccert]);
    } else {
        fs.readFile(config.KMS_PKCS11_CONFIG, 'utf8', function(err, data) {
            if(err) {
                console.log('Native signing can\'t read the Google KMS configuration, signing ' + params.objectid + ' with OpenSSL: ' + err);
                callback(false);
            } else {
                findKeyVersion(data, params).then(function(keyversion) {
                    if(keyversion) {
                        keyVersions[params.publiccert] = keyversion;
                    } else {
                        console.log('Native signing found no Google KMS key version with the CA\'s public key for ' + params.objectid + ', signing with OpenSSL');
                    }
                    callback(keyversion);
                }, function(err) {
                    console.log('Native signing failed to find the Google KMS key version for ' + params.objectid + ', signing with OpenSSL: ' + err);
                    callback(false);
                });
            }
        });
    }
}

var findKeyVersion = async function(kmsconfig, params) {
    let keyrings = (parse(kmsconfig).tokens || []).map(function(token) { return token.key_ring; });
    let objectid = params.objectid;
    let publickey = new crypto.X509Certificate(params.publiccert).publicKey.export({type: 'spki', format: 'der'});
    for(let i = 0; i <= keyrings.length - 1; i++) {
        let versions;
        try {
            [versions] = await kmsClient.listCryptoKeyVersions({parent: keyrings[i] + '/cryptoKeys/' + objectid, filter: 'state=ENABLED'});
        } catch(err) {
            // the key is in another key ring
            if(err.code == 5) {
                continue;
            }
            throw err;
        }
        for(let j = 0; j <= versions.length - 1; j++) {
            let [key] = await kmsClient.getPublicKey({name: versions[j].name});
            if(crypto.createPublicKey(key.pem).export({type: 'spki', format: 'der'}).equals(publickey)) {
                return versions[j].name;
            }
        }
    }
    return false;
}

// called like node-openssl-cert2's x509.CASignCSR, plus the CA's token and object for Google KMS keys
var CASignCSR = function(params, token, callback) {
    try {
        getSigner();
    } catch(err) {
        console.log('Native signing is unavailable, signing with OpenSSL: ' + err);
        openssl2.x509.CASignCSR(params, callback);
        return;
    }
    getKeyVersion(token, function(keyversion) {
        if(keyversion) {
            params.kms = {keyVersion: keyversion};
        }
        signer.x509.CASignCSR(params, function(err, crt) {
            // node-pki-signer's errors are objects that would reach the platform as {}
            callback(err ? String(err) : false, crt);
        });
    });
}

module.exports = {
    enabled: enabled,
    CASignCSR: CASignCSR
}
