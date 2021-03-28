var openssl = require('./openssl');
var opensslcommand = require('./openSSLCommand');
var pkcs11tool = require('./pkcs11ToolCommand');
var yubicopivtool = require('./yubicoPIVToolCommand');
var softhsm2util = require('./softhsm2utilcommand');
var config = require('../config');
var tmp = require('tmp');
var fs = require('fs');
const randomString = require('./randomString')
//const IoTHSM = require('./IoTHSM');
var events = require('events');
var eventEmitter = new events.EventEmitter();

var mapping = {
	'01': '9a',
	'02': '9c',
	'03': '9d',
	'04': '9e',
	'05': '82',
	'06': '83',
	'07': '84',
	'08': '85',
	'09': '86',
	'10': '87',
	'11': '88',
	'12': '89',
	'13': '8a',
	'14': '8b',
	'15': '8c',
	'16': '8d',
	'17': '8e',
	'18': '8f',
	'20': '91',
	'21': '92',
	'22': '93',
	'23': '94',
	'24': '95',
	'25': 'f9'
}

/*var slotsChanged = function () {
    console.log('I hear a scream!');
}

eventEmitter.on('changed', slotsChanged);*/

var modules = [
    config.LIB + '/softhsm/libsofthsm2.so',
    config.LIB + '/x86_64-linux-gnu/libykcs11.so'
]

var cachedslots = {
    slots: [],
    state: 'uninitialized'
};

var readObjects = function(slot, idindex, typeindex, objectindex, callback) {
    if(idindex===null || idindex===false) {
        idindex = 0;
    }
    if(typeindex===null || typeindex===false) {
        typeindex = 0;
    }
    if(objectindex===null || objectindex===false) {
        objectindex = 0;
    }
    /*
    let ids = Object.keys(slot.objects);
    console.log(slot.objects);
    if(typeindex <= types.length - 1) {
        if(objectindex <= Object.keys(slot.objects).length - 1) {
            //console.log(slot.objects[types[typeindex]]);
            readObjects(slot, typeindex, objectindex + 1, callback);
        } else {
            readObjects(slot, typeindex + 1, false, callback);
        }
    } else {
        callback(false);
    }*/
    let ids = Object.keys(slot.objects);
    if(idindex <= ids.length - 1) {
        let types = Object.keys(slot.objects[ids[idindex]]);
        if(typeindex <= types.length - 1) {
            let objects = Object.keys(slot.objects[ids[idindex]][types[typeindex]]);
            if(objectindex <= objects.length - 1) {
                //console.log(objects[objectindex]);
                //console.log(slot.objects[ids[idindex]][types[typeindex]][objects[objectindex]]);
                let type;
                if(slot.objects[ids[idindex]][types[typeindex]][objects[objectindex]].type.toUpperCase()=='CERTIFICATE OBJECT') {
                    type = 'cert';
                } else if(slot.objects[ids[idindex]][types[typeindex]][objects[objectindex]].type.toUpperCase()=='PUBLIC KEY OBJECT') {
                    type = 'pubkey';
                } else {
                    //unknown type
                }
                if(type) {
                    openssl.readPKCS11Object({slotid: slot.hexid, objectid: slot.objects[ids[idindex]][types[typeindex]][objects[objectindex]].ID, type: type, modulePath: slot.modulePath}, function(err, slotout, cmd) {
                        //console.log(cmd);
                        if(err) {
                            //callback(err, false);
                            console.log('Failed to read object');
                            console.log(err);
                            readObjects(slot, idindex, typeindex, objectindex + 1, callback);
                        } else {
                            slot.objects[ids[idindex]][types[typeindex]][objects[objectindex]].base64 = slotout;
                            if(type=='cert') {
                                openssl.getCertInfo(slotout, function(err, attrs, cmd) {
                                    if(err) {
                                        callback(err, false);
                                    } else {
                                        //console.log(attrs);
                                        if(typeof(attrs.subject.commonName)=='string') {
                                            attrs.subject.commonName = [attrs.subject.commonName];
                                        }
                                        let certattrs = attrs;
                                        attrs.distinguishedName = openssl.getDistinguishedName(attrs.subject)
                                        slot.objects[ids[idindex]][types[typeindex]][objects[objectindex]].certinfo = certattrs;
                                        readObjects(slot, idindex, typeindex, objectindex + 1, callback);
                                    }
                                });
                            } else {
                                readObjects(slot, idindex, typeindex, objectindex + 1, callback);
                            }
                        }
                    });
                }
            } else {
                readObjects(slot, idindex, typeindex + 1, false, callback);
            }
        } else {
            readObjects(slot, idindex + 1, false, false, callback);
        }
    } else {
        callback(false);
    }
}

/*var readObjects = function(slot, index, callback) {
    if(index===null || index===false) {
        index = 0;
    }
    if(index <= Object.keys(slot.objects).length - 1) {
        //console.log(slot)
        let type;
        if(slot.objects[index].type.toUpperCase()=='CERTIFICATE OBJECT') {
            type = 'cert';
        } else if(slot.objects[index].type.toUpperCase()=='PUBLIC KEY OBJECT') {
            type = 'pubkey';
        } else {
            //unknown type
        }
        if(type) {
            openssl.readPKCS11Object({slotid: slot.hexid, objectid: slot.objects[index].ID, type: type, modulePath: slot.modulePath}, function(err, slotout, cmd) {
                //console.log(cmd);
                if(err) {
                    //callback(err, false);
                    console.log('Failed to read object');
                    console.log(err);
                    readObjects(slot, index + 1, callback);
                } else {
                    slot.objects[index].base64 = slotout;
                    if(type=='cert') {
                        openssl.getCertInfo(slotout, function(err, attrs, cmd) {
                            if(err) {
                                callback(err, false);
                            } else {
                                let certattrs = attrs;
                                attrs.distinguishedName = openssl.getDistinguishedName(attrs.subject)
                                slot.objects[index].certinfo = certattrs;
                                readObjects(slot, index + 1, callback);
                            }
                        });
                    } else {
                        readObjects(slot, index + 1, callback);
                    }
                }
            });
        } else {
            readObjects(slot, index + 1, callback);
        }
    } else {
        callback(false);
    }
}*/

var getObjects = function(slots, index, callback) {
    if(index===null || index===false) {
        index = 0;
    }
    if(index <= slots.length - 1) {
        //if(slots[index].hasOwnProperty('token state') && slots[index]['token state'] == 'uninitialized') {
        //    getObjects(slots, index + 1, callback);
        //} else {
            openssl.listPKCS11Objects({modulePath: slots[index].modulePath, slotid: slots[index].hexid}, function(err, objectout, cmd) {
                //console.log(cmd);
                if(err) {
                    if(err.indexOf('0xe1')) {
                        getObjects(slots, index + 1, callback);
                    } else {
                        callback(err, false);
                    }
                } else {
                    for(let i = 0; i <= objectout.length - 1; i++) {
                        objectout[i].base64 = null;
                        if(!slots[index].objects.hasOwnProperty(objectout[i].ID)) {
                            slots[index].objects[objectout[i].ID] = {};
                        }
                        if(!slots[index].objects[objectout[i].ID].hasOwnProperty(objectout[i].type)) {
                            slots[index].objects[objectout[i].ID][objectout[i].type] = [];
                        }
                        slots[index].objects[objectout[i].ID][objectout[i].type].push(objectout[i]);
                        //console.log(objectout[i]);
                        //slots[index].objects[objectout[i].ID] = objectout[i];
                        //slots[index].objects.push(objectout[i]);
                    }
                    //console.log(objectout);
                    readObjects(slots[index], false, false, false, function(err) {
                        if(err) {
                            callback(err);
                        } else {
                            getObjects(slots, index + 1, callback);
                        }
                    });
                }
            });
        //}
    } else {
        callback(false);
    }
}

var getSlots = function(slots, index, callback) {
    if(index===null || index===false) {
        index = 0;
    }
    if(index <= modules.length - 1) {
        openssl.listPKCS11Slots({modulePath: modules[index]}, function(err, slotout, cmd) {
            if(err) {
                console.log('Error with module: "' + modules[index] + '"');
                console.log(err);
                console.log('Continuing anyway...');
                getSlots(slots, index + 1, callback);
            } else {
                for(let i = 0; i <= slotout.length - 1; i++) {
                    slotout[i].modulePath = modules[index];
                    slotout[i].objects = {}
                    slots.push(slotout[i]);
                }
                getSlots(slots, index + 1, callback);
            }
        });
    } else {
        callback(false, slots);
    }
}

var deleteObject = function(params, callback) {
    //console.log(params);
    let type;
    if(params.type=='Public Key Object') {
        type = 'pubkey';
    } else if(params.type=='Certificate Object') {
        type = 'cert';
    } else {
        callback('Invalid object type', false);
        return;
    }
    let login;
    if(params.logintype=='User') {
        login = '--login --login-type user --pin ' + params.pin
    } else if(params.logintype=='Security Officer') {
        login = '--login --login-type so --so-pin ' + params.pin
    } else {
        callback('Unrecognized login type', false);
        return;
    }
    let cmd = ['--module ' + params.module + ' ' + login + ' --slot ' + params.slotid + ' --id ' + params.objectid + ' --delete-object --type ' + type];
    if(params.hasOwnProperty('label')) {
        if(params.label) {
            if(params.label!='') {
                cmd.push('--label ' + params.label.split(' ').join('\\ '));
            }
        }

    }
    //console.log(cmd.join(' '));
    pkcs11tool.run(cmd.join(' '), function(err, out) {
        //console.log(out);
        if(err) {
            callback(err, false);
        } else {
            cachedslots.slots = [];
            callback(false, out.stdout);
        }
    });
    //callback(false, false);
}

var deleteHSM2Slot = function(params, callback) {
    let cmd = ['--delete-token --serial ' + params.serial];
    //console.log(cmd);
    softhsm2util.run(cmd.join(' '), function(err, out) {
        //console.log(out);
        if(err) {
            callback(err, false);
        } else {
            cachedslots.slots = [];
            callback(false, out.stdout);
        }
    });
}

var createHSM2Slot = function(params, callback) {
    openssl.listPKCS11Slots({modulePath: config.LIB + '/softhsm/libsofthsm2.so'}, function(err, slotout, cmd) {
        //console.log(cmd);
        if(err) {
            callback(err, false);
        } else {
            var originalslotid = slotout.length - 1;
            let label = params.label.split(' ').join('\\ ');
            //console.log(label)
            let cmd = ['--module ' + config.LIB + '/softhsm/libsofthsm2.so --slot ' + originalslotid + ' --init-token --label ' + label + ' --so-pin ' + params.sopin];
            //let cmd = ['--module ' + config.LIB + '/softhsm/libsofthsm2.so --slot ' + originalslotid + ' --init-token --label \'' + params.label + '\' --so-pin ' + params.sopin];
            //console.log('look here');
            //console.log(cmd);
            pkcs11tool.run(cmd.join(' '), function(err, out) {
                //console.log(out);
                if(err) {
                    callback(err, false);
                } else {
                    openssl.listPKCS11Slots({modulePath: config.LIB + '/softhsm/libsofthsm2.so'}, function(err, slotout, cmd) {
                        //console.log(cmd);
                        if(err) {
                            callback(err, false);
                        } else {
                            let newslotid;
                            for(let i = 0; i <= slotout.length - 1; i++) {
                                if(slotout[i].id==originalslotid) {
                                    newslotid = slotout[i].hexid;
                                    break;
                                }
                            }
                            let cmd = ['--module ' + config.LIB + '/softhsm/libsofthsm2.so --slot ' + newslotid + ' --login --login-type so --so-pin ' + params.sopin + ' --init-pin --pin ' + params.pin];
                            //console.log('look here');
                            //console.log(cmd);
                            pkcs11tool.run(cmd.join(' '), function(err, out) {
                                //console.log(out);
                                if(err) {
                                    callback(err, false);
                                } else {
                                    cachedslots.slots = [];
                                    callback(false, out.stdout);
                                }
                            });
                        }
                    });
                }
            });
        }
    });
}

var prepLabel = function(str) {
    let label;
    //console.log(params.label);
    if(str) {
        if(str != '') {
            label = str.split(' ').join('\\ ');
        } else {
            label = str;
        }
    } else {
        label = str;
    }

    return label;
}

var generateKeyPair = function(params, callback) {
    //console.log('called');
    //console.log(params);
    let login;
    if(params.logintype=='User') {
        login = '--login --login-type user --pin ' + params.pin
    } else if(params.logintype=='Security Officer') {
        login = '--login --login-type so --so-pin ' + params.pin
    } else {
        callback('Unrecognized login type', false);
        return;
    }
    let label = prepLabel(params.label);
    let cmd = ['--module ' + params.module + ' --label ' + label + ' ' + login + ' --keypairgen --slot ' + params.slotid + ' --id ' + params.objectid + ' --key-type ' + params.keytype];
    //console.log(cmd.join(' '));
    pkcs11tool.run(cmd.join(' '), function(err, out) {
        //console.log(out);
        if(err) {
            callback(err, false);
        } else {
            var csroptions = {
                module: params.module,
                hash: 'sha512',
                days: 365,
                subject: {
                    countryName: 'US',
                    commonName: [
                        'TEMPORARY CERT FOR KEY IMPORT'
                    ]
                }
            }
            openssl.selfSignCSRv2({options: csroptions, pkcs11: {pin: config.USERPIN, serial: params.serial, slotid: params.objectid}} , function(err, crt, cmd) {
                if(err) {
                    callback(err, false);
                } else {
                    console.log(crt);
                    //callback(false, crt);
                    //console.log(cmd.files.config);
                    params.cert = crt;
                    console.log(params);
                    importCertificate(params, function(err, resp) {
                        if(err) {
                            callback(err, false);
                        } else {
                            cachedslots.slots = [];
                            callback(false, crt);
                        }
                    });
                }
            });
        }
    });
    //callback(false, false);
}

var abstractImport = function(params, callback) {
    let login;
    if(params.logintype=='User') {
        login = '--login --login-type user --pin ' + params.pin
    } else if(params.logintype=='Security Officer') {
        login = '--login --login-type so --so-pin ' + params.pin
    } else {
        callback('Unrecognized login type', false);
        return;
    }
    var label = prepLabel(params.label);
    if(params.module.indexOf('libykcs') >= 0) {
        randomString.generate({length: 40, characters: '1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'}, function(err, randomstring) {
            if(err) {
                callback(err, false);
            } else {
                var csroptions = {
                    hash: 'sha512',
                    days: 1,
                    subject: {
                        countryName: 'US',
                        commonName: [
                            'TEMPORARY CERT FOR KEY IMPORT'
                        ]
                    }
                }
                openssl.generateCSR(csroptions, params.key, params.keypass, function(err, csr, cmd) {
                    if(err) {
                        callback(err, false);
                    } else {
                        openssl.selfSignCSR(csr, csroptions, params.key, params.keypass, function(err, crt, cmd) {
                            if(err) {
                                callback(err, false);
                            } else {
                                openssl.createPKCS12(crt, params.key, params.keypass, randomstring, false, function(err, pfx, command) {
                                    if(err) {
                                        //console.log(err);
                                        //console.log(command);
                                    } else {
                                        tmp.file(function _tempFileCreated(err, pfxpath, fd, cleanupCallback) {
                                            if (err) {
                                                cleanupCallback();
                                                callback(err, false);
                                            } else {
                                                fs.writeFile(pfxpath, pfx, function() {
                                                    if(err) {
                                                        cleanupCallback();
                                                        callback(err, false);
                                                    } else {
                                                        let cmd = ['-aimport-certificate -aimport-key -k' + params.pin + ' -s' + mapping[params.objectid] + ' -i' + pfxpath + ' -p' + randomstring + ' -KPKCS12'];
                                                        console.log(cmd);
                                                        yubicopivtool.run({cmd: cmd.join(' '), stdin: params.key}, function(err, out) {
                                                            //console.log(out);
                                                            if(err) {
                                                                cleanupCallback();
                                                                callback(err, false);
                                                            } else {
                                                                callback(false, crt);
                                                                /*let cmd = ['rsa -inform pem -in ' + pempath + ' -pubout -outform pem'];
                                                                opensslcommand.run({ cmd: cmd.join(' ') }, function(err, out) {
                                                                    //console.log(out);
                                                                    cleanupCallback();
                                                                    if(err) {
                                                                        callback(err, false);
                                                                    } else {
                                                                        let cmd = ['-averify -aselfsign -v2 --valid-days=365 -P' + params.pin + ' -s' + mapping[params.objectid] + ' -S/CN=piv_auth/OU=test/O=example.com/'];
                                                                        console.log(cmd);
                                                                        console.log(out.stdout.toString());
                                                                        yubicopivtool.run({cmd: cmd.join(' '), stdin: out.stdout.toString()}, function(err, out) {
                                                                            //console.log(out);
                                                                            if(err) {
                                                                                cleanupCallback();
                                                                                callback(err, false);
                                                                            } else {
                                                                                callback(false, out.stdout);
                                                                            }
                                                                        });
                                                                    }
                                                                });*/
                                                            }
                                                        });
                                                    }
                                                });
                                            }
                                        });
                                    }
                                });
                            }
                        });
                    }
                });
            }
        });
    } else {
        //console.log('here');
        openssl.convertPrivPEMtoDER({key: params.key, type: params.keytype, password: params.keypass}, function(err, data) {
            if(err) {
                callback(err, false);
            } else {
                tmp.file(function _tempFileCreated(err, derpath, fd, cleanupCallback) {
                    if (err) {
                        cleanupCallback();
                        callback(err, false);
                    } else {
                        fs.writeFile(derpath, data, function() {
                            if(err) {
                                cleanupCallback();
                                callback(err, false);
                            } else {
                                let cmd = ['--label ' + label + ' --module ' + params.module + ' ' + login + ' --slot ' + params.slotid + ' --id ' + params.objectid + ' --write-object ' + derpath + ' --type privkey'];
                                //console.log(cmd.join(' '));
                                //console.log(data);
                                pkcs11tool.run(cmd.join(' '), function(err, out) {
                                    //console.log(out);
                                    if(err) {
                                        cleanupCallback();
                                        callback(err, false);
                                    } else {
                                        convertPubPEMtoDER(derpath, function(err, out) {
                                            if(err) {
                                                cleanupCallback();
                                                callback(err, false);
                                            } else {
                                                tmp.file(function _tempFileCreated(err, pubkeypath, fd, cleanupCallback) {
                                                    if (err) {
                                                        cleanupCallback();
                                                        callback(err, false);
                                                    } else {
                                                        fs.writeFile(pubkeypath, out, function() {
                                                            if(err) {
                                                                cleanupCallback();
                                                                callback(err, false);
                                                            } else {
                                                                let cmd = ['--label ' + label + ' --module ' + params.module + ' ' + login + ' --slot ' + params.slotid + ' --id ' + params.objectid + ' --write-object ' + pubkeypath + ' --type pubkey'];
                                                                console.log(cmd.join(' '));
                                                                //console.log(data);
                                                                pkcs11tool.run(cmd.join(' '), function(err, out) {
                                                                    cleanupCallback();
                                                                    //console.log(out);
                                                                    if(err) {
                                                                        callback(err, false);
                                                                    } else {
                                                                        var csroptions = {
                                                                            module: params.module,
                                                                            hash: 'sha512',
                                                                            days: 365,
                                                                            subject: {
                                                                                countryName: 'US',
                                                                                commonName: [
                                                                                    'TEMPORARY CERT FOR KEY IMPORT'
                                                                                ]
                                                                            }
                                                                        }
                                                                        openssl.selfSignCSRv2({options: csroptions, pkcs11: {pin: config.USERPIN, serial: params.serial, slotid: params.objectid}} , function(err, crt, cmd) {
                                                                            if(err) {
                                                                                callback(err, false);
                                                                            } else {
                                                                                console.log(crt);
                                                                                //callback(false, crt);
                                                                                //console.log(cmd.files.config);
                                                                                params.cert = crt;
                                                                                console.log(params);
                                                                                importCertificate(params, function(err, resp) {
                                                                                    if(err) {
                                                                                        callback(err, false);
                                                                                    } else {
                                                                                        cachedslots.slots = [];
                                                                                        callback(false, crt);
                                                                                    }
                                                                                });
                                                                            }
                                                                        });
                                                                    }
                                                                });
                                                            }
                                                        });
                                                    }
                                                });
                                            }
                                        });
                                    }
                                });
                            }
                        });
                    }
                });
            }
        });
    }
}

var convertPubPEMtoDER = function(derpath, callback) {
    let cmd = ['rsa -inform der -in ' + derpath + ' -pubout -outform der'];
    opensslcommand.run({ cmd: cmd.join(' ') }, function(err, out) {
        if(err) {
            let cmd = ['ec -inform der -in ' + derpath + ' -pubout -outform der'];
            opensslcommand.run({ cmd: cmd.join(' ') }, function(err, out) {
                if(err) {
                    callback(err, false);
                } else {
                    callback(false, out.stdout);
                }
            });
        } else {
            callback(false, out.stdout);
        }
    });
}

var importPrivateKey = function(params, callback) {
    console.log(params);
    let login;
    if(params.logintype=='User') {
        login = '--login --login-type user --pin ' + params.pin
    } else if(params.logintype=='Security Officer') {
        login = '--login --login-type so --so-pin ' + params.pin
    } else {
        callback('Unrecognized login type', false);
        return;
    }
    abstractImport(params, function(err, pubkey) {
        if(err) {
            callback(err, false);
        } else {
            cachedslots.slots = [];
            callback(false, pubkey);
        }
    });
}

var getCertInfo = function(params, callback) {
    openssl.getCertInfo(params.template, function(err, cert, cmd) {
        if(err) {
            openssl.getCSRInfo(params.template, function(err, cert, cmd) {
                if(err) {
                    callback(err, false);
                } else {
                    callback(false, cert);
                }
            });
        } else {
            callback(false, cert);
        }
    });
}

var generateSelfSigned = function(params, callback) {
    getCertInfo(params, function(err, cert) {
        if(err) {
            callback(err, false);
        } else {
            //console.log(cert);
            //callback(false, cert);
            var csroptions = {
                module: params.module,
                hash: params.hash,
                days: params.days,
                extensions: cert.extensions,
                subject: cert.subject
            }
            openssl.selfSignCSRv2({options: csroptions, pkcs11: {pin: params.pin, serial: params.serial, slotid: params.objectid}} , function(err, crt, cmd) {
                if(err) {
                    callback(err, false);
                } else {
                    //console.log(crt);
                    callback(false, crt);
                    //console.log(cmd.files.config);
                }
            });
        }
    });
    //callback(false, false);
}

var getPublicCert = function(params, callback) {
    //console.log(params);
    if(params.hasOwnProperty('publiccert') && params.publiccert) {
        callback(false, params.publiccert);
    } else {
        openssl.readPKCS11Object({slotid: params.slotid, objectid: params.objectid, type: 'cert', modulePath: params.module}, function(err, out) {
            //console.log(out);
            if(err) {
                callback(err, false);
            } else {
                callback(false, out);
            }
        });
    }
}

var signCSR = function(params, callback) {
    //console.log(params);
    openssl.getCSRInfo(params.csr, function(err, cert, cmd) {
        if(err) {
            callback(err, false);
        } else {
            //console.log(cert);
            //callback(false, cert);
            var csroptions;
            if(params.hasOwnProperty('options')) {
                if(params.options) {
                    csroptions = params.options;
                    csroptions.module = params.module;
                } else {
                    csroptions = {
                        module: params.module,
                        hash: params.hash,
                        days: params.days,
                        extensions: cert.extensions,
                        subject: cert.subject
                    }
                }
            } else {
                csroptions = {
                    module: params.module,
                    hash: params.hash,
                    days: params.days,
                    extensions: cert.extensions,
                    subject: cert.subject
                }
            }
            tmp.dir({unsafeCleanup: true}, function _tempDirCreated(err, path, cleanupCallback) {
                getPublicCert(params, function(err, publiccert) {
                    if(err) {
                        cleanupCallback();
                        console.log(err);
                    } else {
                        //console.log('coming');
                        //console.log(publiccert);
                        fs.writeFile(path + '/ca.crt', publiccert, function(err) {
                            if(err) {
                                cleanupCallback()
                            } else {
                                fs.writeFile(path + '/index.txt', '', function(err) {
                                    if(err) {
                                        cleanupCallback()
                                    } else {
                                        fs.mkdir(path + '/certs', function(err) {
                                            if(err) {
                                                cleanupCallback()
                                            } else {
                                                //console.log(path);
                                                let osslpath;
                                                if(path.indexOf('\\') >= 0) {
                                                    osslpath = path.split('\\').join('\\\\')
                                                } else {
                                                    osslpath = path;
                                                }
                                                //console.log(osslpath);
                                                openssl.CASignCSRv2({csr: params.csr, options: csroptions, persistcapath: osslpath, ca: false, key: false, password: false, pkcs11: {serial: params.serial, pin: params.pin, slotid: params.objectid}}, function(err, crt, cmd) {
                                                    //csr, options, persistcapath, ca, key, password
                                                    //console.log(cmd);
                                                    cleanupCallback()
                                                    if(err) {
                                                        callback(err, false);
                                                    } else {
                                                        //console.log(crt);
                                                        callback(false, crt);
                                                        //console.log(cmd);
                                                    }
                                                });
                                            }
                                        });
                                    }
                                });
                            }
                        });
                    }
                });
            });
        }
    });
    //callback(false, false);
}

var generateCSR = function(params, callback) {
    openssl.getCertInfo(params.template, function(err, cert, cmd) {
        if(err) {
            callback(err, false);
        } else {
            //console.log(cert);
            //callback(false, cert);
            var csroptions = {
                module: params.module,
                hash: params.hash,
                extensions: cert.extensions,
                subject: cert.subject
            }
            openssl.generateCSRv2({options: csroptions, pkcs11: {pin: params.pin, serial: params.serial, slotid: params.objectid}} , function(err, csr, cmd) {
                if(err) {
                    callback(err, false);
                } else {
                    //console.log(csr);
                    callback(false, csr);
                    //console.log(cmd.files.config);
                }
            });
        }
    });
    //callback(false, false);
}

var importCertificate = function(params, callback) {
    console.log(params);
    let login;
    if(params.logintype=='User') {
        login = '--login --login-type user --pin ' + params.pin
    } else if(params.logintype=='Security Officer') {
        login = '--login --login-type so --so-pin ' + params.pin
    } else {
        callback('Unrecognized login type', false);
        return;
    }
    let label = prepLabel(params.label);
    openssl.convertPEMtoDER(params.cert, function(err, data) {
        if(err) {
            callback(err, false);
        } else {
            tmp.file(function _tempFileCreated(err, objectpath, fd, cleanupCallback1) {
                if (err) {
                    cleanupCallback1();
                    callback(err, false);
                } else {
                    fs.writeFile(objectpath, data, function() {
                        if(err) {
                            cleanupCallback1();
                            callback(err, false);
                        } else {
                            let cmd = ['--label ' + label + ' --module ' + params.module + ' ' + login + ' --slot ' + params.slotid + ' --id ' + params.objectid + ' --write-object ' + objectpath + ' --type cert'];
                            //console.log(cmd.join(' '));
                            //console.log(data);
                            pkcs11tool.run(cmd.join(' '), function(err, out) {
                                cleanupCallback1();
                                //console.log(out);
                                if(err) {
                                    callback(err, false);
                                } else {
                                    cachedslots.slots = [];
                                    callback(false, {});
                                }
                            });
                        }
                    });
                }
            });
        }
    });
}

var signCRL = function(params, callback) {
    tmp.dir({unsafeCleanup: true}, function _tempDirCreated(err, path, cleanupCallback) {
        if(err) {
            callback(err, false);
        } else {
            let baseconfig = {
                module: params.module,
                hash: 'sha256',
                subject: {
                    countryName: 'US'
                }
            }
            openssl.generateConfig(baseconfig, true, path, function(err, config) {
                if(err) {
                    cleanupCallback();
                    callback(err, false);
                } else {
                    getPublicCert(params, function(err, publiccert) {
                        if(err) {
                            cleanupCallback();
                            console.log(err);
                        } else {
                            //console.log('coming');
                            //console.log(publiccert);
                            fs.writeFile(path + '/ca.crt', publiccert, function(err) {
                                if(err) {
                                    cleanupCallback()
                                } else {
                                    fs.writeFile(path + '/config.txt', config.join('\r\n'), function(err) {
                                        if(err) {
                                            cleanupCallback();
                                            callback(err, false);
                                        } else {
                                            fs.writeFile(path + '/index.txt', params.database, function(err) {
                                                if(err) {
                                                    cleanupCallback();
                                                    callback(err, false);
                                                } else {
                                                    fs.writeFile(path + '/index.txt.attr', 'unique_subject = no', function(err) {
                                                        if(err) {
                                                            cleanupCallback();
                                                            callback(err, false);
                                                        } else {
                                                            //let momentdate = moment();
                                                            //command = 'ca -startdate ' + momentdate.subtract(1, 'days').toDate() + ' -enddate ' + momentdate.add(1, 'days').toDate() + ' -passin file:' + path + '/pass -config ' + path + '/config.txt' + ' -gencrl -crldays ' + crldays.toString();
                                                            let command = 'ca -engine pkcs11 -keyform engine -keyfile pkcs11:serial=' + params.serial + ';id=%' + params.objectid + ' -passin stdin -config ' + path + '/config.txt' + ' -gencrl -crldays ' + params.days.toString();
                                                            //console.log(command);
                                                            //runOpenSSLCommand(command, path, function(err, out) {
                                                            opensslcommand.run({cmd: command, cwd: path, stdin: params.pin}, function(err, out) {
                                                                cleanupCallback();
                                                                if(err) {
                                                                    callback(err, false);
                                                                } else {
                                                                    callback(null, out.stdout.toString());
                                                                }
                                                            });
                                                        }
                                                    });
                                                }
                                            });
                                        }
                                    });
                                }
                            });
                        }
                    })
                }
            });
        }
    });
}

module.exports = {
    /*reloadHSMs: function() {
        if(cachedslots.state == 'initializing') {
            callback(false, cachedslots);
        } else {
            cachedslots.slots = [];
            this.getSlots();
        } 
    },*/
    deleteHSM2Slot: function(params, callback) {
        deleteHSM2Slot(params, function(err, resp) {
            if(err) {
                callback(err, false);
            } else {
                callback(false, resp);
            }
        });
    },
    signCSR: function(params, callback) {
        signCSR(params, function(err, resp) {
            if(err) {
                callback(err, false);
            } else {
                callback(false, resp);
            }
        });
    },
    signCRL: function(params, callback) {
        signCRL(params, function(err, resp) {
            if(err) {
                callback(err, false);
            } else {
                callback(false, resp);
            }
        });
    },
    generateKeyPair: function(params, callback) {
        generateKeyPair(params, function(err, resp) {
            if(err) {
                //console.log(err);
                callback(err, false);
            } else {
                callback(false, resp);
            }
        });
    },
    generateSelfSigned: function(params, callback) {
        generateSelfSigned(params, function(err, resp) {
            if(err) {
                //console.log(err);
                callback(err, false);
            } else {
                callback(false, resp);
            }
        });
    },
    generateCSR: function(params, callback) {
        generateCSR(params, function(err, resp) {
            if(err) {
                //console.log(err);
                callback(err, false);
            } else {
                callback(false, resp);
            }
        });
    },
    createHSM2Slot: function(params, callback) {
        createHSM2Slot(params, function(err, resp) {
            if(err) {
                callback(err, false);
            } else {
                callback(false, resp);
            }
        });
    },
    deleteObject: function(params, callback) {
        deleteObject(params, function(err, resp) {
            if(err) {
                callback(err, false);
            } else {
                callback(false, resp);
            }
        });
    },
    importPrivateKey: function(params, callback) {
        importPrivateKey(params, function(err, resp) {
            if(err) {
                callback(err, false);
            } else {
                callback(false, resp);
            }
        });
    },
    importCertificate: function(params, callback) {
        importCertificate(params, function(err, resp) {
            if(err) {
                callback(err, false);
            } else {
                callback(false, resp);
            }
        });
    },
    event: eventEmitter,
    getSlots: function(force, callback) {
        //console.log(slots);
        if(cachedslots.state == 'initializing') {
            callback(false, cachedslots);
        } else {
            if(force || cachedslots.slots.length == 0) {
                cachedslots.slots = [];
                //console.log('refresh');
                //openssl.listSlots({}, function(err, slots) {
                getSlots([], false, function(err, slots) {
                    //console.log(slots);
                    cachedslots.state = 'initializing';
                    if(err) {
                        cachedslots.state = 'error';
                        callback(err, false);
                    } else {
                        getObjects(slots, false, function(err) {
                            if(err) {
                                cachedslots.state = 'error';
                                console.log(err);
                            } else {
                                //console.log(util.inspect(slots, {showHidden: false, depth: null}));
                                //console.log(slots);
                                cachedslots.state = 'initialized';
                                cachedslots.slots = slots;
                                //changed(cachedslots);
                                eventEmitter.emit('changed', cachedslots);
                                callback(false, cachedslots);
                            }
                        });
                    }
                });
            } else {
                callback(false, cachedslots);
            }
        }
    }
}