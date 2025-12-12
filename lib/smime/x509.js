var openssl2 = require('../openssl2');
var slotlib = require('../slotlib');
var config = require('../../config');
var moment = require('moment');
const randomString = require('../randomString')
var fs = require('fs');
var pinlib = require('../pin');
const common = require('../common');

var cacert;

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
                                    params.cert.channel.cert = signedcert;
                                    params.cert.channel.certinfo = info.data;
                                    callback(false, signedcert);
                                }
                            });
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
                //console.log(now.diff(startdate, 'seconds') + ' seconds since certificate "not before" date');
                //console.log(enddate.diff(now, 'seconds') + ' seconds til certificate expires');
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
                console.log('No existing cert. Generating a new one...');
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