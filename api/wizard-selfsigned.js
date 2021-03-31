var config = require('../config');
var slotlib = require('../lib/slotlib');
var common = require('../lib/common');
//const apiResponse = require('./apiResponse');

function generateSelfSigned(params, callback) {
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
                    objectid: params.objectid,
                    pin: config.USERPIN,
                    template: params.base64
                }
                slotlib.generateSelfSigned(request, function(err, resp) {
                    if(err) {
                        callback(err, false);
                    } else {
                        if(common.getTokenType(slots.slots[slotindex])=='softhsm') {
                            request.logintype = 'User';
                            request.pin = config.USERPIN;
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
                            request.pin = config.SOPIN;
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