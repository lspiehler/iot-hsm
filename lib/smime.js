var openssl = require('./openssl');
const opensslcommand = require('./openSSLCommand');
var slotlib = require('./slotlib');
var moment = require('moment');
const randomString = require('./randomString')
var tmp = require('tmp');
var fs = require('fs');

var signRequest = function(params, callback) {
    //console.log(params);
    writeSignFiles(params, function(err, signfiles) {
        if(err) {
            callback(err, false);
        } else {
            let cmd = ['cms -sign -outform SMIME -nodetach -inform SMIME -binary -in ' + signfiles.path + '/json.txt -signer ' + signfiles.path + '/signer.pem -inkey ' + signfiles.path + '/signer.key -passin stdin'];
            opensslcommand.run({cmd: cmd.join(' '), stdin: params.key.pass}, function(err, out) {
                if(err) {
                    callback(err, false);
                } else {
                    //console.log(out.stdout.toString());
                    callback(false, out.stdout.toString());
                }
            });
            //callback(false, 'test');
        }
    });
}

var writeSignFiles = function(params, callback) {
    tmp.dir({unsafeCleanup: true}, function _tempDirCreated(err, path, cleanupCallback) {
        if(err) {
            callback(err, false);
        } else {
            fs.writeFile(path + '/json.txt', JSON.stringify(params.json), function(err) {
                if(err) {
                    cleanupCallback();
                    callback(err, false);
                } else {
                    fs.writeFile(path + '/signer.pem', params.cert, function(err) {
                        if(err) {
                            cleanupCallback();
                            callback(err, false);
                        } else {
                            fs.writeFile(path + '/signer.key', params.key.base64, function(err) {
                                if(err) {
                                    cleanupCallback();
                                    callback(err, false);
                                } else {
                                    callback(false, {path: path, cleanupCallback: cleanupCallback});
                                }
                            });
                        }
                    });
                }
            });
        }
    });
}

var getKey = function(cert, callback) {
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

var getShortCert = function(cert, callback) {
    getKey(cert, function(err, key) {
        if(err) {
            callback(err, false);
        } else {
            if(cert.channel.key === false) {
                cert.channel.key = key;
            }
            //let now = moment(new Date()).utc().toDate()
            var csroptions = {
                module: '/usr/lib/x86_64-linux-gnu/libykcs11.so',
                hash: 'sha512',
                startdate: moment.utc(new Date()).add(-2, 'minutes').toDate(),
                enddate: moment.utc(new Date()).add(1, 'days').toDate(),
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
                            console.log(signedcert);
                            callback(false, signedcert);
                        }
                    });
                }
            });
            //console.log(csroptions);
            //callback(false, key);
        }
    });
}

module.exports = {
    getShortCert: function(cert, callback) {
        getShortCert(cert, function(err, shortcert) {
            if(err) {
                callback(err, false);
            } else {
                callback(false, shortcert);
            }
        });
    },
    signRequest: function(cert, callback) {
        signRequest(cert, function(err, shortcert) {
            if(err) {
                callback(err, false);
            } else {
                callback(false, shortcert);
            }
        });
    }
}