var openssl2 = require('../openssl2');
var slotlib = require('../slotlib');
var config = require('../../config');
var moment = require('moment');
const randomString = require('../randomString')
var fs = require('fs');
var pinlib = require('../pin');
const common = require('../common');

var cacert;

//channel certificates get a new key at every renewal; the previous key keeps decrypting for a few minutes because the platform may already have encrypted a request to it
//requests treat a certificate within 5 minutes of expiring as expired, so the lifetime is at least 10 minutes
const lifetime = Math.max(parseInt(config.CHANNELCERTMINUTES) || 1440, 10);
const previousminutes = 10;

var getCACert = function(callback) {
    if(cacert) {
        callback(false, cacert);
    } else {
        fs.readFile('./certs/smime_ca_' + config.PLATFORMFQDN.split('.').join('_') + '.pem', function(err, contents) {
            if(err) {
                callback(err, false);
            } else {
                cacert = contents.toString();
                callback(false, contents.toString());
            }
        });
    }
}

var getKey = function(cert, callback) {
    //console.log(cert);
    if(cert.channel.key) {
        callback(false, { base64: cert.channel.key.base64, pass: cert.channel.key.pass});
    } else {
        newKey(callback);
    }
}

var newKey = function(callback) {
    randomString.generate({length: 40, characters: '1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'}, function(err, randomstring) {
        if(err) {
            callback(err, false);
        } else {
            var rsakeyoptions = {
                encryption: {
                    password: randomstring,
                    cipher: 'aes256'
                },
                rsa_keygen_bits: 2048,
                //rsa_keygen_pubexp: 65537,
                format: 'PKCS8'
            }

            openssl2.keypair.generateRSA(rsakeyoptions, function(err, privkey, cmd) {
                if(err) {
                    callback(err, false);
                } else {
                    callback(false, { base64: privkey.data, pass: randomstring});
                }
            });
        }
    });
}

var generateNewCert = function(params, callback) {
    // console.log(params);
    let hashalg = 'sha256'
    if(params.cert.hasOwnProperty('private_key')) {
        hashalg = common.getAllowedHashAlg(params.cert.private_key);
    }
    var csroptions = {
        hash: hashalg,
        startdate: moment.utc(new Date()).add(-5, 'minutes').toDate(),
        enddate: moment.utc(new Date()).add(lifetime, 'minutes').toDate(),
        //startdate: moment(new Date(), "YYYY-MM-DD HH:mm:ss", "America/Chicago").utc().add(-5, 'minutes').toDate(),
        //enddate: moment(new Date(), "YYYY-MM-DD HH:mm:ss", "America/Chicago").utc().add(5, 'minutes').toDate(),
        //days: 600,
        subject: {
            commonName: [
                'IoT HSM SMIME Cert for PKIaaS.io Validation'
            ]
        },
        extensions: {
            keyUsage: {
                critical: true,
                usages: [
                    'digitalSignature',
                    'keyEncipherment',
                    'dataEncipherment'
                ]
            },
            extendedKeyUsage: {
                critical: true,
                usages: [
                    'emailProtection'
                ]	
            }
        }
    }
    openssl2.csr.create({ options: csroptions, key: params.key.base64, password: params.key.pass}, function(err, csr) {
        if(err) {
            callback(err, false);
        } else {
            //callback(false, csr);
            pinlib.getPins({serial: params.cert['token serial']},function(err, pins) {
                if(err) {
                    callback('Failed to get pins', false);
                } else {
                    //console.log(pins);
                    let userpin;
                    if(pins) {
                        userpin = pins.USERPIN;
                    } else {
                        userpin = config.USERPIN;
                    }
                    //console.log(userpin);
                    slotlib.signCSR({ publiccert: params.cert.base64, slotid: params.cert['token hexid'], csr: csr.data, options: csroptions, module: params.cert.module, serial: params.cert['token serial'], pin: userpin, objectid: params.cert['ID']}, function(err, signedcert) {
                        if(err) {
                            callback(err, false);
                        } else {
                            openssl2.x509.parse({cert: signedcert}, function(err, info) {
                                if(err) {
                                    callback(err, false);
                                } else {
                                    // console.log(info);
                                    callback(false, { cert: signedcert, certinfo: info.data });
                                }
                            });
                        }
                    });
                }
            });
        }
    });
}

//renewals that overlap (a scheduled one and one a request needs) share one new key and certificate
var renewCert = function(cert, callback) {
    if(cert.channel.renewing) {
        cert.channel.renewing.push(callback);
        return;
    }
    cert.channel.renewing = [callback];
    let finish = function(err, signedcert) {
        let callbacks = cert.channel.renewing;
        cert.channel.renewing = false;
        for(let i = 0; i <= callbacks.length - 1; i++) {
            callbacks[i](err, signedcert);
        }
    }
    newKey(function(err, key) {
        if(err) {
            finish(err, false);
        } else {
            generateNewCert({cert: cert, key: key}, function(err, signed) {
                if(err) {
                    finish(err, false);
                } else {
                    //swap the key and certificate in one step so nothing sees a mismatched pair
                    if(cert.channel.cert) {
                        cert.channel.previous = {
                            cert: cert.channel.cert,
                            key: cert.channel.key,
                            until: Date.now() + previousminutes * 60 * 1000
                        }
                    }
                    cert.channel.key = key;
                    cert.channel.cert = signed.cert;
                    cert.channel.certinfo = signed.certinfo;
                    finish(false, signed.cert);
                }
            });
        }
    });
}

var getCert = function(cert, callback) {
    if(cert.channel.cert) {
        let startdate = moment(cert.channel.certinfo.attributes['Not Before']);
        let enddate = moment(cert.channel.certinfo.attributes['Not After']);
        let now = moment();
        //console.log(now.diff(startdate, 'seconds') + ' seconds since certificate "not before" date');
        //console.log(enddate.diff(now, 'seconds') + ' seconds til certificate expires');
        if(now.diff(startdate, 'seconds') >= 0) {
            if(enddate.diff(now, 'seconds') >= 300) {
                callback(false, cert.channel.cert);
                return;
            } else {
                console.log('Existing cert is expired or within 5 minutes of expiring. Generating a new one...');
            }
        } else {
            console.log('Existing cert is not valid yet. Generating a new one...');
        }
    } else {
        console.log('No existing cert. Generating a new one...');
    }
    renewCert(cert, callback);
}

module.exports = {
    getCert: function(cert, callback) {
        getCert(cert, function(err, cert) {
            if(err) {
                callback(err, false);
            } else {
                callback(false, cert);
            }
        });
    },
    renewCert: function(cert, callback) {
        renewCert(cert, callback);
    },
    lifetime: lifetime,
    getKey: function(cert, callback) {
        getKey(cert, function(err, key) {
            if(err) {
                callback(err, false);
            } else {
                callback(false, key);
            }
        });
    },
    getCACert: function(callback) {
        getCACert(function(err, cacert) {
            if(err) {
                callback(err, false);
            } else {
                callback(false, cacert);
            }
        });
    }
}