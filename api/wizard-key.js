var config = require('../config');
var slotlib = require('../lib/slotlib');
var common = require('../lib/common');
var pinlib = require('../lib/pin');
//const apiResponse = require('./apiResponse');

function processKeyPrep(params, callback) {
    slotlib.getSlots(false, function(err, slots) {
        if(err) {
            callback(err, false);
        } else {
            pinlib.getPins({serial: params.serial},function(err, pins) {
                if(err) {
                    callback('Failed to get pins', false);
                } else {
                    //console.log(pins);
                    let userpin;
                    let sopin;
                    if(pins) {
                        userpin = pins.USERPIN;
                        sopin = pins.SOPIN;
                    } else {
                        userpin = config.USERPIN;
                        sopin = config.SOPIN;
                    }
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
                            pin: sopin,
                            signpin: userpin
                        }
                        if(params.keyAcquisition == 'generate') {
                            if(common.getTokenType(slots.slots[slotindex])=='softhsm') {
                                request.logintype = 'User';
                                request.pin = userpin;
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
                                request.pin = userpin;
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