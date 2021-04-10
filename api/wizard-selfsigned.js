var config = require('../config');
var slotlib = require('../lib/slotlib');
var common = require('../lib/common');
var pinlib = require('../lib/pin');
//const apiResponse = require('./apiResponse');

function generateSelfSigned(params, callback) {
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
                            objectid: params.objectid,
                            pin: userpin,
                            template: params.base64
                        }
                        slotlib.generateSelfSigned(request, function(err, resp) {
                            if(err) {
                                callback(err, false);
                            } else {
                                if(common.getTokenType(slots.slots[slotindex])=='softhsm') {
                                    request.logintype = 'User';
                                    request.pin = userpin;
                                    request.cert = resp;
                                    request.type = 'Certificate Object';
                                    slotlib.deleteObject(request, function(err, resp) {
                                        if(err) {
                                            callback(err, false);
                                        } else {
                                            slotlib.importCertificate(request, function(err, resp) {
                                                if(err) {
                                                    callback(err, false);
                                                } else {
                                                    //console.log(resp);
                                                    callback(false, resp);
                                                }
                                            });
                                        }
                                    });
                                } else {
                                    request.logintype = 'Security Officer';
                                    request.pin = sopin;
                                    request.cert = resp;
                                    slotlib.importCertificate(request, function(err, resp) {
                                        if(err) {
                                            callback(err, false);
                                        } else {
                                            //console.log(resp);
                                            callback(false, resp);
                                        }
                                    });
                                }
                            }
                        });
                    }
                }
            });
        }
    });
}

module.exports = {
    handler: function(params, callback) {
        generateSelfSigned(params, function(err, resp) {
            if(err) {
                callback(err, resp);
            } else {
                callback(false, resp);
            }
        });
    }
}