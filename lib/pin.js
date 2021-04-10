var fs = require('fs');
var Cryptr;
var cryptr;
require("machine-uuid")(function(id) {
    Cryptr = require('cryptr');
    cryptr = new Cryptr(id);
})
var pins;

function setPins(params, callback) {
    if(pins) {

    } else {
        pins = {};
    }
    pins[params.serial] = {
        USERPIN: params.userpin,
        SOPIN: params.sopin
    }
    if(params.persist) {
        fs.writeFile(__dirname + '/../state/pins.js', cryptr.encrypt(JSON.stringify(pins)), function(err) {
            if(err) {
                console.log('Failed to PINs to disk');
                console.trace(err);
                callback(true);
            } else {
                callback(false, pins);
            }
        });
    } else {
        callback(false, pins);
    }
}

function getPins(params, callback) {
    if(pins) {
        if(pins.hasOwnProperty(params.serial)) {
            callback(false, pins[params.serial]);
        } else {
            callback(false, false);
        }
    } else {
        fs.readFile(__dirname + '/../state/pins.js', 'utf8', function(err, contents) {
            if(err) {
                //pins are not set
                callback(false, false);
            } else {
                try {
                    pins = JSON.parse(cryptr.decrypt(contents));
                    if(pins.hasOwnProperty(params.serial)) {
                        callback(false, pins[params.serial]);
                    } else {
                        callback(false, false);
                    }
                } catch (e) {
                    //pin state file is not in valid json format
                    callback(false, false);
                }
            }
        });
    }
}

module.exports = {
    getPins: function(params, callback) {
        getPins(params, function(err, resp) {
            if(err) {
                callback(err, false);
            } else {
                callback(false, resp);
            }
        });
    },
    setPins: function(params, callback) {
        setPins(params, function(err, resp) {
            if(err) {
                callback(err, false);
            } else {
                callback(false, 'PINs set successfully');
            }
        });
    }
}