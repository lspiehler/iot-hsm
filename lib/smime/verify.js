const customOpenSSLCommand = require('../openSSLCommand');
var tmp = require('tmp');
var fs = require('fs');

var verify = function(params, callback) {
    //console.log(params);
    tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback) {
        if (err) {
            callback(err, false);
        } else {
            fs.writeFile(path, params.ca, function() {
                if(err) {
                    cleanupCallback();
                    callback(err, false);
                } else {
                    let command = 'smime -pk7out -inform SMIME -outform pem';
                    customOpenSSLCommand.run({cmd: command, stdin: params.smime}, function(err, out) {
                        if(err) {
                            callback(err, false);
                        } else {
                            //console.log(out.stdout);
                            let command = 'pkcs7 -inform pem -outform pem -print_certs';
                            customOpenSSLCommand.run({cmd: command, stdin: out.stdout}, function(err, out) {
                                //console.log(out);
                                if(err) {
                                    callback(err, false);
                                } else {
                                    const begin = '-----BEGIN CERTIFICATE-----';
                                    const end = '-----END CERTIFICATE-----';
                                    var placeholder = out.stdout.toString().indexOf(begin);
                                    var certs = [];
                                    var endoutput = false;
                                    if(placeholder <= 0) {
                                        endoutput = true;
                                        callback('No certificate found in openssl command response', 'No certificate found in openssl command response', 'openssl ' + command);
                                        return;
                                    }
                                    var shrinkout = out.stdout.toString().substring(placeholder);
                                    //console.log(shrinkout);
                                    while(!endoutput) {
                                        let endofcert = shrinkout.indexOf(end);
                                        certs.push(shrinkout.substring(0, endofcert) + end);
                                        shrinkout = shrinkout.substring(endofcert); 
                                        
                                        placeholder = shrinkout.indexOf(begin);
                                        //console.log(placeholder);
                                        if(placeholder <= 0) {
                                            endoutput = true;
                                        } else {
                                            shrinkout = shrinkout.substring(placeholder);
                                        }
                                    }
                                    //console.log(out.stdout);
                                    let command = 'cms -verify -inform SMIME -outform SMIME -binary -CAfile ' + path;
                                    customOpenSSLCommand.run({cmd: command, stdin: params.smime}, function(err, out) {
                                        //console.log(out);
                                        if(err) {
                                            callback(err, false);
                                        } else {
                                            //console.log(out);
                                            callback(false, {certs: certs, data: out.stdout.toString()});
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
        verify(params, function(err, resp) {
            if(err) {
                //console.log();
                callback(err, false);
            } else {
               callback(false, resp);
            }
        });
    }
}