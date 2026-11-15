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
// CA certificate → {version} once its Google KMS key version is found, or {version: false, retry} when it
// wasn't, so a CA without a match doesn't repeat the KMS lookups on every signature
var keyVersions = {};
// how long such a CA signs through the module before the lookup is tried again
const LOOKUPRETRY = 60 * 60 * 1000;

var enabled = function() {
    return ['1', 'true', 'yes', 'on'].indexOf(String(config.NATIVESIGNING).toLowerCase()) >= 0;
}

// created when first needed: creating it looks for Google credentials, which only KMS tokens have
var getKmsClient = function() {
    if(!kmsClient) {
        const { KeyManagementServiceClient } = require('@google-cloud/kms');
        kmsClient = new KeyManagementServiceClient();
    }
    return kmsClient;
}

var getSigner = function() {
    if(!signer) {
        // loaded only when enabled: node-pki-signer needs Node 24.11 or newer
        const { createSigner } = require('node-pki-signer');
        signer = createSigner({
            binpath: config.opensslbinpath,
            kms: getKmsClient(),
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
    } else if(keyVersions.hasOwnProperty(params.publiccert) && (keyVersions[params.publiccert].version || keyVersions[params.publiccert].retry > Date.now())) {
        callback(keyVersions[params.publiccert].version);
    } else {
        fs.readFile(config.KMS_PKCS11_CONFIG, 'utf8', function(err, data) {
            if(err) {
                console.log('Native signing can\'t read the Google KMS configuration, signing ' + params.objectid + ' with OpenSSL: ' + err);
                callback(false);
            } else {
                findKeyVersion(data, params).then(function(keyversion) {
                    if(keyversion) {
                        keyVersions[params.publiccert] = {version: keyversion};
                    } else {
                        keyVersions[params.publiccert] = {version: false, retry: Date.now() + LOOKUPRETRY};
                        console.log('Native signing found no Google KMS key version with the CA\'s public key for ' + params.objectid + ', signing with OpenSSL for the next hour');
                    }
                    callback(keyversion);
                }, function(err) {
                    keyVersions[params.publiccert] = {version: false, retry: Date.now() + LOOKUPRETRY};
                    console.log('Native signing failed to find the Google KMS key version for ' + params.objectid + ', signing with OpenSSL for the next hour: ' + err);
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
            [versions] = await getKmsClient().listCryptoKeyVersions({parent: keyrings[i] + '/cryptoKeys/' + objectid, filter: 'state=ENABLED'});
        } catch(err) {
            // the key is in another key ring
            if(err.code == 5) {
                continue;
            }
            throw err;
        }
        for(let j = 0; j <= versions.length - 1; j++) {
            let [key] = await getKmsClient().getPublicKey({name: versions[j].name});
            if(crypto.createPublicKey(key.pem).export({type: 'spki', format: 'der'}).equals(publickey)) {
                return versions[j].name;
            }
        }
    }
    return false;
}

// node-pki-signer's errors are objects that would reach the platform as {}; the platform gets the message without
// the KMS key's project, location and key ring
var platformMessage = function(err) {
    let message = err instanceof Error ? err.message : String(err);
    return message.replace(/projects\/[^/\s'"]+\/locations\/[^/\s'"]+\/keyRings\/[^/\s'"]+\//g, '');
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
            if(err) {
                console.log('Native signing failed for ' + token.objectid + ': ' + err);
                callback(platformMessage(err), crt);
            } else {
                if(crt && crt.signedBy == 'openssl') {
                    console.log('Native signing used OpenSSL for ' + token.objectid);
                }
                callback(false, crt);
            }
        });
    });
}

// The final certificate for a CT precertificate is built by node-pki-signer whether native signing is on or not:
// OpenSSL can't keep the precertificate's serial and dates. With native signing off, the token's key signs through
// OpenSSL's pkcs11-provider as before, so pkcs11js never opens the token. A Google KMS key signs through the KMS API,
// or through libkmsp11 with OpenSSL when the KMS backend can't sign it; either way node-pki-signer needs its key
// version.
var finalSigner = false;
var finalCertificates = undefined;

// whether this agent can sign CT final certificates: node-pki-signer 0.4.0 or later loads (Node 24.11 or newer)
var canSignFinalCertificates = function() {
    if(finalCertificates === undefined) {
        try {
            finalCertificates = typeof require('node-pki-signer').signFinalCertificate == 'function';
        } catch(err) {
            console.log('CT final certificates are unavailable: node-pki-signer doesn\'t load: ' + err);
            finalCertificates = false;
        }
    }
    return finalCertificates;
}

var getFinalSigner = function() {
    if(enabled()) {
        return getSigner();
    }
    if(!finalSigner) {
        const { createSigner } = require('node-pki-signer');
        // node-pki-signer creates its KMS client when a KMS key first signs
        finalSigner = createSigner({
            binpath: config.opensslbinpath,
            backends: ['openssl-pkcs11', 'kms']
        });
    }
    return finalSigner;
}

// params: {precertificate, sctList (Buffer), ca, pkcs11}, the CA's own certificate and key; token as for CASignCSR.
// node-pki-signer refuses a precertificate this key didn't sign. Calls back with the final certificate's PEM.
var signFinalCertificate = function(params, token, callback) {
    let signer;
    try {
        signer = getFinalSigner();
    } catch(err) {
        callback('This IoT HSM agent can\'t sign CT final certificates: ' + platformMessage(err), false);
        return;
    }
    getKeyVersion(token, function(keyversion) {
        if(keyversion) {
            params.kms = {keyVersion: keyversion};
        } else if(token.module.split('/').at(-1) == 'libkmsp11.so') {
            callback('This IoT HSM agent can\'t sign CT final certificates with this Google KMS key: its key version wasn\'t found (see the agent\'s log)', false);
            return;
        }
        signer.signFinalCertificate(params).then(function(result) {
            console.log('Signed a CT final certificate for ' + token.objectid + ' with the ' + result.backend + ' backend');
            callback(false, result.data);
        }, function(err) {
            console.log('Signing a CT final certificate failed for ' + token.objectid + ': ' + err);
            // OpenSSL's errors name the key's PKCS#11 URI, with the token's serial number
            callback(platformMessage(err).replace(/pkcs11:[^\s'"]+/g, 'the token\'s key'), false);
        });
    });
}

module.exports = {
    enabled: enabled,
    CASignCSR: CASignCSR,
    canSignFinalCertificates: canSignFinalCertificates,
    signFinalCertificate: signFinalCertificate
}
