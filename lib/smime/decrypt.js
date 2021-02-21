const customOpenSSLCommand = require('../openSSLCommand');
var tmp = require('tmp');
var fs = require('fs');

var decrypt = function(params, callback) {
    //console.log(params);
    tmp.dir({unsafeCleanup: true}, function _tempDirCreated(err, path, cleanupCallback) {
        if(err) {
            callback(err, false);
        } else {
            fs.writeFile(path + '/encrypted.txt', params.data, function(err) {
                if(err) {
                    cleanupCallback()
                } else {
                    fs.writeFile(path + '/smime.pem', params.cert, function(err) {
                        if(err) {
                            cleanupCallback()
                        } else {
                            fs.writeFile(path + '/smime.key', params.key.base64, function(err) {
                                if(err) {
                                    cleanupCallback()
                                } else {
                                    let command = 'cms -decrypt -binary -in ' + path + '/encrypted.txt -recip ' + path + '/smime.pem -inkey ' + path + '/smime.key -passin stdin'
                                    //console.log(command);
                                    customOpenSSLCommand.run({cmd: command, stdin: params.key.pass}, function(err, out) {
                                        //console.log(out);
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
        decrypt(params, function(err, resp) {
            if(err) {
                //console.log();
                callback(err, false);
            } else {
               callback(false, resp);
            }
        });
    }
}