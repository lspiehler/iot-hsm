var config = require('../config');
var slotlib = require('../lib/slotlib');
var common = require('../lib/common');
//const apiResponse = require('./apiResponse');

function processKeyPrep(params, callback) {
    slotlib.getSlots(false, function(err, slots) {
        if(err) {
            callback(err, false);
        } else {
            //console.log('here');
            //console.log(params);
            let slotindex = common.getSlotIndex(slots, params.serial);
            if(slotindex < 0) {
                callback('Failed to find token with serial ' + params.serial, false);
            } else {
                //console.log(common.getTokenType(slots.slots[slotindex]));
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
                    if(common.getTokenType(slots.slots[slotindex])=='softhsm') {
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
                    if(common.getTokenType(slots.slots[slotindex])=='softhsm') {
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