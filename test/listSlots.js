var openssl = require('../lib/openssl');
const util = require('util');

var modules = [
    '/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so',
    '/usr/lib/x86_64-linux-gnu/libykcs11.so'
]

var cachedslots = false;

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
            //console.log(cmd);
            if(err) {
                callback(err, false);
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

getSlots([], false, function(err, slots) {
    if(err) {
        callback(err, false);
    } else {
        getObjects(slots, false, function(err) {
            if(err) {
                console.log(err);
            } else {
                console.log(util.inspect(slots, {showHidden: false, depth: null}));
                //console.log(slots);
            }
        });
    }
});