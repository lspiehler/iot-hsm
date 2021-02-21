const smime = require('./smime');
const smimelib = require('./smime/index');
const smimeca = require('./SMIMECA');
const https = require('https');
const SMIMECA = require('./SMIMECA');

var certs = [];
var subscribeid;
var publishid;

function request(params, callback) {
    var data = [];

    var req = https.request(params.options, function(res) {

        res.on('data', function(chunk) {
            data.push(chunk);
        });

        res.on('end', function(){
            let responsebody = JSON.parse(new Buffer.concat(data).toString());
            let response = {
                statusCode: res.statusCode,
                statusMessage: res.statusMessage,
                headers: res.headers,
                data: responsebody
            }
            if(response.error_message) {
                callback(response.error_message, response);
            } else {
                callback(false, response);
            }
        });

        res.on('error', function(e){
            callback(e.message, false);
        });
    });

    req.on('error', function(e){
        callback(e.message, false);
    });

    if(params.body) {
        req.write(params.body);
    } else {
        //req.write();
    }

    req.end();
}

var sendRequest = function(cert, params, callback) {
    //console.log(params);
    var options = {
        host: 'cyopki.com',
        port: 443,
        path: '/api/public/getiotconnectiondata/' + params.serial + '/' + params.thumbprint,
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    }

    request({options: options, body: JSON.stringify(params)}, function(err, resp) {
        if(err) {
            callback(err, false);
        } else {
            SMIMECA.getCert(function(err, ca) {
                if(err) {
                    console.log(err);
                    callback(err, false);
                } else {
                    smimelib.verify({ca: ca, smime: resp.data.smime}, function(err, verify) {
                        if(err) {
                            console.log(err);
                            callback(err, false);
                        } else {
                            //console.log('verify');
                            //console.log(verify);
                            //console.log(cert);
                            smimelib.decrypt({ data: verify.data, cert: cert.channel.cert, key: cert.channel.key }, function(err, decrypt) {
                                if(err) {
                                    console.log(err);
                                    callback(err, false);
                                } else {
                                    console.log(decrypt);
                                    callback(false, JSON.parse(decrypt));
                                }
                            });
                        }
                    });
                }
            });
        }
    });
}

var createRequest = function(jsonrequest, cert, issued, callback) {
    smimelib.sign({ data: JSON.stringify(jsonrequest), cert: issued, key: cert.channel.key }, function(err, request) {
        if(err) {
            callback(err, false);
        } else {
            callback(false, request);
        }
    });
}

var getChannels = function(certs, index, callback) {
    if(index===null || index===false) {
        index = 0;
    }
    if(index <= certs.length - 1) {
        //console.log(certs[index]);
        smime.getShortCert(certs[index], function(err, cert) {
            if(err) {
                callback(err, false);
            } else {
                certs[index].channel.id = null;
                certs[index].channel.cert = cert;
                let jsonrequest = {
                    serial: certs[index].certinfo.attributes['Serial Number'].toLowerCase().split(':').join(''),
                    thumbprint: certs[index].certinfo.attributes['Thumbprint'].toLowerCase().split(':').join('')
                }
                createRequest(jsonrequest, certs[index], cert, function(err, request) {
                    if(err) {
                        callback(err, false);
                    } else {
                        //callback(false, request);
                        jsonrequest.smime = request;
                        //console.log(request);
                        sendRequest(certs[index], jsonrequest, function(err, response) {
                            if(err) {
                                callback(err, false);
                            } else {
                                getChannels(certs, index + 1, callback);
                            }
                        });
                    }
                });
            }
        });
    } else {
        callback(false, certs);
    }
}

var connectSlots = function(slots, callback) {
    //console.log(slots);
    for(let i = 0; i <= slots.length - 1; i++) {
        let slotids = Object.keys(slots[i].objects);
        for(let j = 0; j <= slotids.length - 1; j++) {
            //console.log(objects);
            let objects = Object.keys(slots[i].objects[slotids[j]]);
            for(let k = 0; k <= objects.length - 1; k++) {
                if(objects[k]=='Certificate Object') {
                    for(let l = 0; l <= slots[i].objects[slotids[j]][objects[k]].length - 1; l++) {
                        //console.log(slots[i].objects[slotids[j]][objects[k]][l].subject);
                        if(slots[i].objects[slotids[j]][objects[k]][l].subject.indexOf('PIV Attestation') < 0) {
                            let cert = Object.assign({}, slots[i].objects[slotids[j]][objects[k]][l]);
                            cert['token serial'] = slots[i]['serial num'];
                            cert['token hexid'] = slots[i]['hexid'];
                            cert['token id'] = slots[i]['id'];
                            cert['token label'] = slots[i]['token label'];
                            cert['token pin'] = '123456';
                            cert['module'] = slots[i]['modulePath'];
                            cert['channel'] = {
                                id: null,
                                key: false
                            }
                            certs.push(cert);
                            //console.log(slots[i].objects[slotids[j]][objects[k]][l]);
                        }
                    }
                }
            }
        }
    }
    callback(false, certs);
}

module.exports = {
    connectSlots: function(slots, callback) {
        connectSlots(slots, function(err, certs) {
            if(err) {
                callback(err);
            } else {
                //console.log(certs);
                getChannels(certs, false, function(err) {
                    if(err) {
                        //console.log(err);
                        callback(err, false);
                    } else {
                        //console.log(certs);
                        callback(false, certs);
                    }
                });
                //callback(certs);
            }
        });
    }
}