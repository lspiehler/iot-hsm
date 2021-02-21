var fs = require('fs');

var cert = false;

var getCert = function(callback) {
    if(cert) {
        callback(false, cert);
    } else {
        fs.readFile('./certs/pkiaas_smime_ca.pem', function(err, contents) {
            if(err) {
                callback(err, false);
            } else {
                cert = contents;
                callback(false, contents);
            }
        });
    }
}

module.exports = {
    getCert: function(callback) {
        getCert(function(err, cert) {
            if(err) {
                callback(err, false);
            } else {
                callback(false, cert);
            }
        });
    }
}