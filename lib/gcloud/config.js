const yaml = require('js-yaml');
const fs = require('fs');
const config = require('../../config');
const openssl2 = require('../openssl2');

module.exports = {
    write: function(json, callback) {
        const yamlStr = yaml.dump(json);
        // console.log(yamlStr);
        let persistPath = __dirname + '/../../state/pkcs11-kms.yml';
        fs.writeFile(persistPath, yamlStr, {mode: 0o644}, function(err) {
            if(err) {
                callback(true, err);
            } else {
                // also write to tmpPath where there's no docker mount and we can control the permissions
                let tmpPath = __dirname + '/../../tmp/pkcs11-kms.yml';
                fs.writeFile(tmpPath, yamlStr, {mode: 0o644}, function(err) {
                    if(err) {
                        fs.unlink(persistPath, (deleteErr) => {
                            callback(err, false);
                        });
                    } else {
                        openssl2.pkcs11.listSlots({modulePath: config.LIB + '/kms/libkmsp11.so'}, function(err, pkcs11slots) {
                            if(err) {
                                fs.unlink(persistPath, (deleteErr) => {
                                    // callback(err, false);
                                });
                                fs.unlink(tmpPath, (deleteErr) => {
                                    // callback(err, false);
                                });
                                callback(err, false);
                            } else {
                                // console.log(pkcs11slots);
                                openssl2.pkcs11.listObjects({modulePath: config.LIB + '/kms/libkmsp11.so', slotid: pkcs11slots.data[0].hexid}, function(err, objects) {
                                    //console.log(cmd);
                                    if(err) {
                                        fs.unlink(persistPath, (deleteErr) => {
                                            // callback(err, false);
                                        });
                                        fs.unlink(tmpPath, (deleteErr) => {
                                            // callback(err, false);
                                        });
                                        callback(err, false);
                                    } else {
                                        // console.log(objects);
                                        var csroptions = {
                                            // module: params.module,
                                            hash: 'sha256',
                                            days: 365,
                                            subject: {
                                                countryName: 'US',
                                                commonName: [
                                                    'TEMPORARY CERT FOR KEY IMPORT'
                                                ]
                                            }
                                        };
                                        openssl2.x509.selfSignCSR({
                                            options: csroptions,
                                            pkcs11: {
                                                uri: openssl2.common.encodePKCS11URI({
                                                    serial: pkcs11slots.data[0]['serial num'],
                                                    object: objects.data[0].label,
                                                    type: 'private'
                                                }),
                                                pin: '1234',
                                                modulePath: config.LIB + '/kms/libkmsp11.so'
                                            }
                                        }, function(err, crt) {
                                            if(err) {
                                                fs.unlink(persistPath, (deleteErr) => {
                                                    // callback(err, false);
                                                });
                                                fs.unlink(tmpPath, (deleteErr) => {
                                                    // callback(err, false);
                                                });
                                                callback(err, false);
                                            } else {
                                                callback(false, yamlStr);
                                            }
                                        });
                                    }
                                });
                                // Process the pkcs11slots as needed
                            }
                        });
                    }
                });
            }
        });
    }
}