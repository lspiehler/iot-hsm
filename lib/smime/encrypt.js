const customOpenSSLCommand = require('../openSSLCommand');
var tmp = require('tmp');
var fs = require('fs');

var encrypt = function(params, callback) {
    //console.log(params);
    tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback) {
        if (err) {
            callback(err, false);
        } else {
            fs.writeFile(path, params.cert, function() {
                if(err) {
                    cleanupCallback();
                    callback(err, false);
                } else {
                    let command = 'cms -encrypt -binary -outform SMIME -aes256 -recip ' + path;
                    customOpenSSLCommand.run({cmd: command, stdin: params.data}, function(err, out) {
                        cleanupCallback();
                        if(err) {
                            callback(err, false);
                        } else {
                            callback(false, out.stdout);
                        }
                    });
                }
            });
        }
    });
}

module.exports = {
    handler: function(params, callback) {
        encrypt(params, function(err, resp) {
            if(err) {
                //console.log();
                callback(err, false);
            } else {
               callback(false, resp);
            }
        });
    }
}