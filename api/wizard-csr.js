var config = require('../config');
var slotlib = require('../lib/slotlib');
var common = require('../lib/common');
var pinlib = require('../lib/pin');
//const apiResponse = require('./apiResponse');

function generateCSR(params, callback) {
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
                    if(pins) {
                        userpin = pins.USERPIN;
                    } else {
                        userpin = config.USERPIN;
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
                        slotlib.generateCSR(request, function(err, resp) {
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
    });
}

module.exports = {
    handler: function(params, callback) {
        generateCSR(params, function(err, resp) {
            if(err) {
                callback(err, resp);
            } else {
                callback(false, resp);
            }
        });
    }
}