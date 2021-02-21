const verify = require('./verify'); 
const encrypt = require('./encrypt'); 
const decrypt = require('./decrypt'); 
const x509 = require('./x509');
const sign = require('./sign');

module.exports = {
    verify: function(params, callback) {
        verify.handler(params, function(err, result) {
            if(err) {
                callback(err, false);
            } else {
                callback(false, result);
            }
        });
    },
    encrypt: function(params, callback) {
        encrypt.handler(params, function(err, result) {
            if(err) {
                callback(err, false);
            } else {
                callback(false, result);
            }
        });
    },
    decrypt: function(params, callback) {
        decrypt.handler(params, function(err, result) {
            if(err) {
                callback(err, false);
            } else {
                callback(false, result);
            }
        });
    },
    sign: function(params, callback) {
        sign.handler(params, function(err, result) {
            if(err) {
                callback(err, false);
            } else {
                callback(false, result);
            }
        });
    },
    x509: x509
}