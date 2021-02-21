const customOpenSSLCommand = require('../openSSLCommand');
var tmp = require('tmp');
var fs = require('fs');

var sign = function(params, callback) {
    //console.log(params);
    tmp.dir({unsafeCleanup: true}, function _tempDirCreated(err, path, cleanupCallback) {
        if(err) {
            callback(err, false);
        } else {
            fs.writeFile(path + '/encrypted.txt', params.data, function(err) {
                if(err) {
                    cleanupCallback()
                } else {
                    fs.writeFile(path + '/smime.pem', params.cert, function() {
                        if(err) {
                            cleanupCallback();
                            callback(err, false);
                        } else {
                            fs.writeFile(path + '/smime.key', params.key.base64, function() {
                                if(err) {
                                    cleanupCallback();
                                    callback(err, false);
                                } else {
                                    let command = 'cms -sign -outform SMIME -nodetach -inform SMIME -binary -in ' + path + '/encrypted.txt -signer ' + path + '/smime.pem -inkey ' + path + '/smime.key -passin stdin';
                                    customOpenSSLCommand.run({cmd: command, stdin: params.key.pass}, function(err, out) {
                                        //console.log(out);
                                        cleanupCallback();
                                        if(err) {
                                            callback(err, false);
                                        } else {
                                            callback(false, out.stdout.toString());
                                        }
                                    });
                                }
                            });
                        }
                    });
                }
            });
        }
    });
}

module.exports = {
    handler: function(params, callback) {
        sign(params, function(err, resp) {
            if(err) {
                //console.log();
                callback(err, false);
            } else {
               callback(false, resp);
            }
        });
    }
}