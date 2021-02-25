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

var getCert = function(cert, callback) {
    getKey(cert, function(err, key) {
        if(err) {
            callback(err, false);
        } else {
            if(cert.channel.key === false) {
                cert.channel.key = key;
            }
            if(cert.channel.cert) {
                let enddate = moment(cert.channel.certinfo.attributes['Not After']);
                console.log(enddate);
                callback(false, cert.channel.cert);
            } else {
                //let now = moment(new Date()).utc().toDate()
                var csroptions = {
                    module: '/usr/lib/x86_64-linux-gnu/libykcs11.so',
                    hash: 'sha512',
                    startdate: moment.utc(new Date()).add(-1, 'days').toDate(),
                    enddate: moment.utc(new Date()).add(6, 'days').toDate(),
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
                openssl.generateCSRv2({ options: csroptions, key: key.base64, password: key.pass}, function(err, csr, cmd) {
                    if(err) {
                        callback(err, false);
                    } else {
                        //callback(false, csr);
                        slotlib.signCSR({ publiccert: cert.base64, slotid: cert['token hexid'], csr: csr, options: csroptions, module: cert.module, serial: cert['token serial'], pin: cert['token pin'], objectid: cert['ID']}, function(err, signedcert) {
                            if(err) {
                                callback(err, false);
                            } else {
                                openssl.getCertInfo(signedcert, function(err, info) {
                                    if(err) {
                                        callback(err, false);
                                    } else {
                                        console.log(info);
                                        cert.channel.cert = signedcert;
                                        cert.channel.certinfo = info;
                                        callback(false, signedcert);
                                    }
                                });
                            }
                        });
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