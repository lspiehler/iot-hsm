const smimelib = require('./smime/index');
const slotlib = require('./slotlib');
const pubnublib = require('./pubnub');
const https = require('https');

var pubnub = false;

var certs = [];
var subscribeid = false;
var publishid = false;

function findCA(ca) {
    for(let i = 0; i <= certs.length - 1; i++) {
        if(ca.serial==certs[i].certinfo.attributes['Serial Number'].split(':').join('').toLowerCase() && ca.thumbprint==certs[i].certinfo.attributes['Thumbprint'].split(':').join('').toLowerCase()) {
            return certs[i];
        }
    }
    return false;
}

function messageReceived(message) {
    //console.log(message);
    if(message.message.type=='solicit signature') {
        console.log(pubnub.getUUID());
        let msg = {
            type: 'services offerred',
            uuid: pubnub.getUUID()
        }
        pubnub.sendMessage({channel: message.channel, message: msg}, function(status, response) {
            if(status.error) {
                console.log('Failed sending pubnub message');
                console.log(status.error);
            }
        });
    } else if(message.message.type=='signature request') {
        if(message.message.uuid==pubnub.getUUID()) {
            let ca = findCA(message.message.request.ca);
            if(ca) {
                slotlib.signCSR({ publiccert: ca.base64, slotid: ca['token hexid'], csr: message.message.request.csr, options: message.message.request.options, module: ca.module, serial: ca['token serial'], pin: ca['token pin'], objectid: ca['ID']}, function(err, signedcert) {
                    if(err) {
                        let msg = {
                            type: 'signature response',
                            success: false,
                            message: err
                        }
                        pubnub.sendMessage({channel: message.channel, message: msg}, function(status, response) {
                            if(status.error) {
                                console.log('Failed sending pubnub message');
                                console.log(status.error);
                            }
                        });
                    } else {
                        let msg = {
                            type: 'signature response',
                            success: true,
                            message: signedcert
                        }
                        pubnub.sendMessage({channel: message.channel, message: msg}, function(status, response) {
                            if(status.error) {
                                console.log('Failed sending pubnub message');
                                console.log(status.error);
                            }
                        });
                    }
                });
            } else {
                let msg = {
                    type: 'signature response',
                    success: false,
                    message: 'Failed to find CA on HSM'
                }
                pubnub.sendMessage({channel: message.channel, message: msg}, function(status, response) {
                    if(status.error) {
                        console.log('Failed sending pubnub message');
                        console.log(status.error);
                    }
                });
            }
        } else {
            console.log('Signing request is not for me');
        }
    } else {
        console.log('ignoring unknown pubnub message');
    }
}

function request(params, callback) {
    var data = [];

    var req = https.request(params.options, function(res) {

        res.on('data', function(chunk) {
            data.push(chunk);
        });

        res.on('end', function(){
            //console.log(res.statusCode);
            //console.log(res.statusMessage);
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
            if(resp.data.success) {
                //console.log(resp);
                smimelib.x509.getCACert(function(err, ca) {
                    if(err) {
                        console.log(err);
                        callback(err, false);
                    } else {
                        smimelib.verify({ca: ca, smime: resp.data.data}, function(err, verify) {
                            if(err) {
                                console.log(err);
                                callback(err, false);
                            } else {
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
            } else {
                callback(err, false);
            }
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
        smimelib.x509.getCert(certs[index], function(err, cert) {
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
                                publishid = response.publishKey;
                                subscribeid = response.subscribeKey;
                                certs[index].channel.id = response.channel_id;
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
        certs = [];
        subscribeid = false;
        publishid = false;
        if(pubnub) {
            pubnub.unsubscribeAll();
        }
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
                        let channels = [];
                        for (let i = 0; i <= certs.length - 1; i++) {
                            if(certs[i].channel.id) {
                                channels.push(certs[i].channel.id);
                            }
                        }
                        //console.log(channels);
                        if(pubnub) {
                            pubnub.subscribe({channels: channels});
                        } else {
                            pubnub = new pubnublib({subscribeKey: subscribeid, publishKey: publishid, channels: channels});
                            pubnub.event.on('message', function(message) {
                                messageReceived(message);
                            });
                        }
                    }
                });
                //callback(certs);
            }
        });
    }
}