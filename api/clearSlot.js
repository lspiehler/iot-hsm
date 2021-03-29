var config = require('../config');
var slotlib = require('../lib/slotlib');
var common = require('../lib/common');

function clearSlot(params, callback) {
    slotlib.getSlots(false, function(err, slots) {
        if(err) {
            callback(err, false);
        } else {
            console.log('here');
            console.log(params);
            let slotindex = common.getSlotIndex(slots, params.serial);
            if(slotindex < 0) {
                callback('Failed to find token with serial ' + params.serial, false);
            } else {
                console.log(common.getTokenType(slots.slots[slotindex]));
                let request = {
                    slotid: slots.slots[slotindex]['hexid'],
                    module: slots.slots[slotindex]['modulePath'],
                    type: 'Private Key Object',
                    objectid: params.objectid,
                    //label: slots.slots[slotindex]['objects'][params.objectid][],
                    logintype: 'Security Officer',
                    pin: config.SOPIN
                }
                if(common.getTokenType(slots.slots[slotindex])=='softhsm') {
                    request.logintype = 'User';
                    request.pin = config.USERPIN;
                    slotlib.deleteObject(request, function(err, resp) {
                        if(err) {
                            callback(err, false);
                        } else {
                            request.type = 'Public Key Object';
                            slotlib.deleteObject(request, function(err, resp) {
                                if(err) {
                                    callback(err, false);
                                } else {
                                    request.type = 'Certificate Object';
                                    slotlib.deleteObject(request, function(err, resp) {
                                        if(err) {
                                            callback(err, false);
                                        } else {
                                            callback(false, resp);
                                        }
                                    });
                                }
                            });
                        }
                    });
                } else {
                    slotlib.deleteObject(request, function(err, resp) {
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
        clearSlot(params, function(err, resp) {
            if(err) {
                callback(err, resp);
            } else {
                callback(false, resp);
            }
        });
    }
}