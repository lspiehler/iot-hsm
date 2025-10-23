var openssl2 = require('./openssl2');
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
var moment = require('moment');
//const base64url = require('base64url');

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
                    openssl2.pkcs11.readObject({slotid: slot.hexid, objectid: slot.objects[ids[idindex]][types[typeindex]][objects[objectindex]].ID, type: type, modulePath: slot.modulePath}, function(err, object) {
                        //console.log(cmd);
                        if(err) {
                            //callback(err, false);
                            console.log('Failed to read object');
                            console.log(err);
                            readObjects(slot, idindex, typeindex, objectindex + 1, callback);
                        } else {
                            slot.objects[ids[idindex]][types[typeindex]][objects[objectindex]].base64 = object.data;
                            if(type=='cert') {
                                openssl2.x509.parse({cert: object.data}, function(err, attrs) {
                                    if(err) {
                                        callback(err, false);
                                    } else {
                                        //console.log(attrs.data);
                                        if(typeof(attrs.data.subject.commonName)=='string') {
                                            attrs.data.subject.commonName = [attrs.data.subject.commonName];
                                        }
                                        let certattrs = attrs.data;
                                        attrs.data.distinguishedName = openssl2.x509.getDistinguishedName(attrs.data.subject)
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

var getObjects = function(slots, index, callback) {
    if(index===null || index===false) {
        index = 0;
    }
    if(index <= slots.length - 1) {
        //if(slots[index].hasOwnProperty('token state') && slots[index]['token state'] == 'uninitialized') {
        //    getObjects(slots, index + 1, callback);
        //} else {
            openssl2.pkcs11.listObjects({modulePath: slots[index].modulePath, slotid: slots[index].hexid}, function(err, objects) {
                //console.log(cmd);m
                if(err) {
                    if(err.indexOf('0xe1')) {
                        getObjects(slots, index + 1, callback);
                    } else {
                        callback(err, false);
                    }
                } else {
                    for(let i = 0; i <= objects.data.length - 1; i++) {
                        if(objects.data[i].type == 'Certificate Object' && objects.data[i].label.indexOf('X.509 Certificate for PIV Attestation') != 0) {
                            //console.log(objects.data[i]);
                            objects.data[i].base64 = null;
                            if(!slots[index].objects.hasOwnProperty(objects.data[i].ID)) {
                                slots[index].objects[objects.data[i].ID] = {};
                            }
                            if(!slots[index].objects[objects.data[i].ID].hasOwnProperty(objects.data[i].type)) {
                                slots[index].objects[objects.data[i].ID][objects.data[i].type] = [];
                            }
                            slots[index].objects[objects.data[i].ID][objects.data[i].type].push(objects.data[i]);
                            //console.log(objects.data[i]);
                            //slots[index].objects[objects.data[i].ID] = objects.data[i];
                            //slots[index].objects.push(objects.data[i]);
                        }
                    }
                    //console.log(objects.data);
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
        openssl2.pkcs11.listSlots({modulePath: modules[index]}, function(err, pkcs11slots) {
            if(err) {
                console.log('Error with module: "' + modules[index] + '"');
                console.log(err);
                console.log('Continuing anyway...');
                getSlots(slots, index + 1, callback);
            } else {
                for(let i = 0; i <= pkcs11slots.data.length - 1; i++) {
                    pkcs11slots.data[i].modulePath = modules[index];
                    pkcs11slots.data[i].objects = {}
                    slots.push(pkcs11slots.data[i]);
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
    } else if(params.type=='Private Key Object') {
        type = 'privkey';
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
    openssl2.pkcs11.listSlots({modulePath: config.LIB + '/softhsm/libsofthsm2.so'}, function(err, pkcs11slots) {
        //console.log(cmd);
        if(err) {
            callback(err, false);
        } else {
            var originalslotid = pkcs11slots.data.length - 1;
            let label = prepLabel(params.label);
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
                    openssl2.pkcs11.listSlots({modulePath: config.LIB + '/softhsm/libsofthsm2.so'}, function(err, pkcs11slots) {
                        //console.log(cmd);
                        if(err) {
                            callback(err, false);
                        } else {
                            let newslotid;
                            for(let i = 0; i <= pkcs11slots.data.length - 1; i++) {
                                if(pkcs11slots.data[i].id==originalslotid) {
                                    newslotid = pkcs11slots.data[i].hexid;
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
    // console.log(params);
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
            openssl2.x509.selfSignCSR({options: csroptions, pkcs11: {pin: params.signpin, serial: params.serial, objectid: params.objectid, modulePath: params.module}} , function(err, crt) {
                if(err) {
                    callback(err, false);
                } else {
                    //callback(false, crt);
                    //console.log(cmd.files.config);
                    params.cert = crt.data;
                    //console.log(params);
                    importCertificate(params, function(err, resp) {
                        if(err) {
                            callback(err, false);
                        } else {
                            cachedslots.slots = [];
                            callback(false, crt.data);
                        }
                    });
                }
            });
        }
    });
    //callback(false, false);
}

var abstractImport = function(params, callback) {
    // console.log(params);
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
                openssl2.csr.create({options: csroptions, key: params.key, password: params.keypass}, function(err, csr) {
                    if(err) {
                        callback(err, false);
                    } else {
                        openssl2.x509.selfSignCSR({csr: csr.data, options: csroptions, key: params.key, password: params.keypass, modulePath: params.module}, function(err, crt) {
                            if(err) {
                                callback(err, false);
                            } else {
                                openssl2.x509.createPKCS12({cert: crt.data, key: params.key, password: params.keypass, pkcs12pass: randomstring}, function(err, pfx) {
                                    if(err) {
                                        //console.log(err);
                                        //console.log(command);
                                    } else {
                                        tmp.file(function _tempFileCreated(err, pfxpath, fd, cleanupCallback) {
                                            if (err) {
                                                cleanupCallback();
                                                callback(err, false);
                                            } else {
                                                fs.writeFile(pfxpath, pfx.data, function() {
                                                    if(err) {
                                                        cleanupCallback();
                                                        callback(err, false);
                                                    } else {
                                                        let cmd = ['-aimport-certificate -aimport-key -k' + params.pin + ' -s' + mapping[params.objectid] + ' -i' + pfxpath + ' -p' + randomstring + ' -KPKCS12'];
                                                        //console.log(cmd);
                                                        yubicopivtool.run({cmd: cmd.join(' '), stdin: params.key}, function(err, out) {
                                                            //console.log(out);
                                                            if(err) {
                                                                cleanupCallback();
                                                                callback(err, false);
                                                            } else {
                                                                callback(false, crt.data);
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
        openssl2.keypair.convertPEMToDER({key: params.key, type: params.keytype, password: params.keypass, decrypt: true}, function(err, der) {
            if(err) {
                callback(err, false);
            } else {
                tmp.file(function _tempFileCreated(err, derpath, fd, cleanupCallback) {
                    if (err) {
                        cleanupCallback();
                        callback(err, false);
                    } else {
                        fs.writeFile(derpath, der.data, function() {
                            if(err) {
                                cleanupCallback();
                                callback(err, false);
                            } else {
                                let cmd = ['--label ' + label + ' --module ' + params.module + ' ' + login + ' --slot ' + params.slotid + ' --id ' + params.objectid + ' --write-object ' + derpath + ' --type privkey'];
                                //console.log(cmd.join(' '));
                                //console.log(der.data);
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
                                                                //console.log(cmd.join(' '));
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
                                                                        openssl2.x509.selfSignCSR({options: csroptions, pkcs11: {pin: params.pin, serial: params.serial, objectid: params.objectid, modulePath: params.module}} , function(err, crt) {
                                                                            if(err) {
                                                                                callback(err, false);
                                                                            } else {
                                                                                //console.log(crt);
                                                                                //callback(false, crt);
                                                                                //console.log(cmd.files.config);
                                                                                params.cert = crt.data;
                                                                                //console.log(params);
                                                                                importCertificate(params, function(err, resp) {
                                                                                    if(err) {
                                                                                        callback(err, false);
                                                                                    } else {
                                                                                        cachedslots.slots = [];
                                                                                        callback(false, crt.data);
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
    //console.log(params);
    openssl2.x509.parse({cert: params.template}, function(err, cert) {
        if(err) {
            openssl2.csr.parse({csr: params.template}, function(err, cert) {
                if(err) {
                    callback(err, false);
                } else {
                    callback(false, cert.data);
                }
            });
        } else {
            callback(false, cert.data);
        }
    });
}

var generateSelfSigned = function(params, callback) {
    console.log(params);
    getCertInfo(params, function(err, cert) {
        if(err) {
            callback(err, false);
        } else {
            //console.log(cert);
            //callback(false, cert);
            let now = moment();
            let enddate = moment(cert.attributes['Not After']);
            let days = enddate.diff(now, 'days');
            var csroptions = {
                module: params.module,
                hash: params.hash,
                days: days,
                extensions: cert.extensions,
                subject: cert.subject
            }
            openssl2.x509.selfSignCSR({options: csroptions, pkcs11: {pin: params.pin, serial: params.serial, objectid: params.objectid, modulePath: params.module}} , function(err, crt) {
                if(err) {
                    callback(err, false);
                } else {
                    //console.log(crt);
                    callback(false, crt.data);
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
        openssl2.pkcs11.readObject({slotid: params.slotid, objectid: params.objectid, type: 'cert', modulePath: params.module}, function(err, object) {
            //console.log(out);
            if(err) {
                callback(err, false);
            } else {
                callback(false, object.data);
            }
        });
    }
}

var signCMS = function(params, callback) {

    let data = params.data;
    if(params.encoding == 'binary') {
        data = Buffer.from(base64url.toBase64(params.data), 'base64');
    }

    openssl2.smime.sign({
        inform: params.inform,
        outform: params.outform,
        cert: params.publiccert,
        data: data,
        encoding: params.encoding,
        addcerts: params.addcerts,
        smimecap: params.smimecap,
        pkcs11: {
            pin: params.pin,
            modulePath: params.module,
            serial: params.serial,
            objectid: params.objectid
        }
    }, function(err, cms, cmd) {
        if(err) {
            callback(err, false);
        } else {
            // console.log(cms);
            callback(false, cms.data.toString());
        }
    });
}

var signCSR = function(params, callback) {
    //console.log(params);
    openssl2.csr.parse({csr: params.csr}, function(err, cert, cmd) {
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
                        extensions: cert.data.extensions,
                        subject: cert.data.subject
                    }
                }
            } else {
                csroptions = {
                    module: params.module,
                    hash: params.hash,
                    days: params.days,
                    extensions: cert.data.extensions,
                    subject: cert.data.subject
                }
            }
            tmp.dir({unsafeCleanup: true}, function _tempDirCreated(err, path, cleanupCallback) {
                openssl2.x509.CASignCSR({csr: params.csr, options: csroptions, ca: params.publiccert, pkcs11: {serial: params.serial, pin: params.pin, objectid: params.objectid, modulePath: params.module}}, function(err, crt) {
                    //openssl.CASignCSRv2({csr: params.csr, options: csroptions, persistcapath: osslpath, ca: false, key: false, password: false, pkcs11: {serial: params.serial, pin: params.pin, slotid: params.objectid}}, function(err, crt, cmd) {
                    //csr, options, persistcapath, ca, key, password
                    //console.log(cmd);
                    //cleanupCallback()
                    if(err) {
                        callback(err, false);
                    } else {
                        //console.log(crt);
                        callback(false, crt.data);
                        //console.log(cmd);
                    }
                });

            });
        }
    });
    //callback(false, false);
}

var generateCSR = function(params, callback) {
    // console.log(params);
    openssl2.x509.parse({cert: params.template}, function(err, cert) {
        if(err) {
            callback(err, false);
        } else {
            //console.log(cert);
            //callback(false, cert);
            var csroptions = {
                module: params.module,
                hash: params.hash,
                extensions: cert.data.extensions,
                subject: cert.data.subject
            }
            openssl2.csr.create({options: csroptions, pkcs11: {pin: params.pin, serial: params.serial, objectid: params.objectid, modulePath: params.module}} , function(err, csr) {
                if(err) {
                    callback(err, false);
                } else {
                    //console.log(csr);
                    callback(false, csr.data);
                    //console.log(cmd.files.config);
                }
            });
        }
    });
    //callback(false, false);
}

var importCertificate = function(params, callback) {
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
    openssl2.x509.convertPEMtoDER(params.cert, function(err, der) {
        if(err) {
            callback(err, false);
        } else {
            tmp.file(function _tempFileCreated(err, objectpath, fd, cleanupCallback1) {
                if (err) {
                    cleanupCallback1();
                    callback(err, false);
                } else {
                    fs.writeFile(objectpath, der.data, function() {
                        if(err) {
                            cleanupCallback1();
                            callback(err, false);
                        } else {
                            let cmd = ['--label ' + label + ' --module ' + params.module + ' ' + login + ' --slot ' + params.slotid + ' --id ' + params.objectid + ' --write-object ' + objectpath + ' --type cert'];
                            //console.log(cmd.join(' '));
                            //console.log(der.data);
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
    // console.log("Sign CRL");
    // console.log(params);
    openssl2.crl.generate({
        ca: params.publiccert,
        crldays: params.days.toString(),
        database: params.database,
        pkcs11: {
            pin: params.pin, serial: params.serial, objectid: params.objectid, modulePath: params.module
        }
    }, function(err, crl) {
        if(err) {
            callback(err, false);
        } else {
            callback(false, crl.data);
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
    signCMS: function(params, callback) {
        signCMS(params, function(err, resp) {
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