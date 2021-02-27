var openssl = require('../openssl');
var slotlib = require('../slotlib');
var moment = require('moment');
const randomString = require('../randomString')
var fs = require('fs');

var cacert;

var getCACert = function(callback) {
    if(cacert) {
        callback(false, cacert);
    } else {
        fs.readFile('./certs/pkiaas_smime_ca.pem', function(err, contents) {
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

                openssl.generateRSAPrivateKey(rsakeyoptions, function(err, privkey, cmd) {
                    if(err) {
                        callback(err, false);
                    } else {
                        callback(false, { base64: privkey, pass: randomstring});
                    }
                });
            }
        });
    }
}

var generateNewCert = function(params, callback) {
    var csroptions = {
        module: '/usr/lib/x86_64-linux-gnu/libykcs11.so',
        hash: 'sha512',
        startdate: moment.utc(new Date()).add(-5, 'minutes').toDate(),
        enddate: moment.utc(new Date()).add(10, 'minutes').toDate(),
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
    openssl.generateCSRv2({ options: csroptions, key: params.key.base64, password: params.key.pass}, function(err, csr, cmd) {
        if(err) {
            callback(err, false);
        } else {
            //callback(false, csr);
            slotlib.signCSR({ publiccert: params.cert.base64, slotid: params.cert['token hexid'], csr: csr, options: csroptions, module: params.cert.module, serial: params.cert['token serial'], pin: params.cert['token pin'], objectid: params.cert['ID']}, function(err, signedcert) {
                if(err) {
                    callback(err, false);
                } else {
                    openssl.getCertInfo(signedcert, function(err, info) {
                        if(err) {
                            callback(err, false);
                        } else {
                            //console.log(info);
                            params.cert.channel.cert = signedcert;
                            params.cert.channel.certinfo = info;
                            callback(false, signedcert);
                        }
                    });
                }
            });
        }
    });
}

var getCert = function(cert, callback) {
    getKey(cert, function(err, key) {
        if(err) {
            callback(err, false);
        } else {
            if(cert.channel.key === false) {
                cert.channel.key = key;
            }
            if(cert.channel.cert) {
                let startdate = moment(cert.channel.certinfo.attributes['Not Before']);
                let enddate = moment(cert.channel.certinfo.attributes['Not After']);
                let now = moment();
                console.log(now.diff(startdate, 'seconds') + ' seconds since certificate "not before" date');
                console.log(enddate.diff(now, 'seconds') + ' seconds til certificate expires');
                if(now.diff(startdate, 'seconds') >= 0) {
                    if(enddate.diff(now, 'seconds') >= 300) {
                        callback(false, cert.channel.cert);
                        return;
                    } else {
                        console.log('Existing cert is expired or within 5 minutes of expiring. Generating a new one...');
                        generateNewCert({cert: cert, key: key}, function(err, signedcert) {
                            if(err) {
                                callback(err, false);
                            } else {
                                callback(false, signedcert);
                            }
                        });
                    }
                } else {
                    console.log('Existing cert is not valid yet. Generating a new one...');
                    generateNewCert({cert: cert, key: key}, function(err, signedcert) {
                        if(err) {
                            callback(err, false);
                        } else {
                            callback(false, signedcert);
                        }
                    });
                }
            } else {
                generateNewCert({cert: cert, key: key}, function(err, signedcert) {
                    if(err) {
                        callback(err, false);
                    } else {
                        callback(false, signedcert);
                    }
                });
            }
        }
    });
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