var config = require('../config');
var slotlib = require('../lib/slotlib');
//const apiResponse = require('./apiResponse');

function getSlotIndex(slots, serial) {
    for(let i = 0; i <= slots.slots.length - 1; i++) {
        //console.log(serial);
        //console.log(slots.slots[i]['serial num']);
        if(slots.slots[i]['serial num']==serial) {
            return i;
        }
    }
    return -1;
}

function getTokenType(slot) {
    //console.log('here');
    //console.log(slot);
    if(slot.modulePath.indexOf('libykcs') >= 0) {
        return 'yubikey'
    } else {
        return 'softhsm';
    }
}

function processKeyPrep(params, callback) {
    slotlib.getSlots(false, function(err, slots) {
        if(err) {
            callback(err, false);
        } else {
            console.log('here');
            console.log(params);
            let slotindex = getSlotIndex(slots, params.serial);
            if(slotindex < 0) {
                callback('Failed to find token with serial ' + params.serial, false);
            } else {
                console.log(getTokenType(slots.slots[slotindex]));
                let request = {
                    serial: params.serial,
                    slotid: slots.slots[slotindex]['hexid'],
                    module: slots.slots[slotindex]['modulePath'],
                    keytype: params.keytype,
                    objectid: params.objectid,
                    logintype: 'Security Officer',
                    pin: config.SOPIN
                }
                if(params.keyAcquisition == 'generate') {
                    if(getTokenType(slots.slots[slotindex])=='softhsm') {
                        request.logintype = 'User';
                        request.pin = config.USERPIN;
                    }
                    //console.log(generate);
                    slotlib.generateKeyPair(request, function(err, resp) {
                        if(err) {
                            callback(err, false);
                        } else {
                            callback(false, resp);
                        }
                    });
                } else {
                    if(getTokenType(slots.slots[slotindex])=='softhsm') {
                        request.logintype = 'User';
                        request.pin = config.USERPIN;
                    }
                    request.key = params.key;
                    request.keypass = params.keypass;
                    slotlib.importPrivateKey(request, function(err, resp) {
                        if(err) {
                            callback(err, false);
                        } else {
                            callback(false, resp);
                        }
                    });
                }
            }
        }
    });
}

module.exports = {
    handler: function(params, callback) {
        processKeyPrep(params, function(err, resp) {
            if(err) {
                callback(err, resp);
            } else {
                callback(false, resp);
            }
        });
    }
}