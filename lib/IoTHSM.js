const smimelib = require('./smime/index');
const slotlib = require('./slotlib');
const pubnublib = require('./pubnub');
const https = require('https');
var zlib = require('zlib');
var config = require('../config');
var requests = [];
var messages = [];
var pubnub = false;
var busy = false;
var certs = [];
var subscribeid = false;
var publishid = false;
var moment = require('moment');
const defaultttl = 5;

var verifyMessage = function(message, callback) {
    smimelib.x509.getCACert(function(err, ca) {
        if(err) {
            console.log(err);
            callback(err, false);
        } else {
            smimelib.verify({ca: ca, smime: message}, function(err, verify) {
                if(err) {
                    console.log(err);
                    callback(err, false);
                } else {
                    callback(false, verify);
                }
            });
        }
    });
}

var sendEncryptedMessage = function(params, callback) {
    //console.log(params);
    let input = Buffer.from(params.signed, 'utf8');
    zlib.deflate(input, function(err, buf) {
        if(err) {
            callback(err, false);
        } else {
            smimelib.encrypt({cert: params.enccert, data: buf}, function(err, smimeenc) {
                if(err) {
                    callback(err, false);
                } else {
                    //console.log('about to sign encrypted message');
                    sendSignedMessage({publisher: params.publisher, channel: params.channel, cert: params.signcert, signed: smimeenc, unsigned: params.unsigned}, function(err, resp) {
                        if(err) {
                            callback(err, false);
                        } else {
                            callback(false, resp);
                        }
                    });
                }
            });
        }
    });
}

var sendSignedMessage = function(params, callback) {
    //console.log(cert);
    smimelib.x509.getCert(params.cert, function(err, newcert) {
        if(err) {
            callback(err, false);
        } else {
            //console.log(cert);
            //cert.channel.cert = newcert;
            smimelib.sign({cert: newcert, key: params.cert.channel.key, data: params.signed}, function(err, smimesign) {
                if(err) {
                    callback(err, false);
                } else {
                    //console.log(smimesign);
                    params.unsigned.smime = smimesign
                    //console.log(params.unsigned);
                    //pubnub.sendMessage({meta: {uuid: params.publisher}, channel: params.channel, message: params.unsigned}, function(status, response) {
                    pubnub.sendMessage({channel: params.channel, message: params.unsigned}, function(status, response) {
                        if(status.error) {
                            callback(status.error, status);
                        } else {
                            callback(false, response);
                        }
                    });
                }
            });
        }
    });
}

function findCA(ca) {
    for(let i = 0; i <= certs.length - 1; i++) {
        if(ca.serial==certs[i].certinfo.attributes['Serial Number'].split(':').join('').toLowerCase() && ca.thumbprint==certs[i].certinfo.attributes['Thumbprint'].split(':').join('').toLowerCase()) {
            return i;
        }
    }
    return -1;
}

function processSignature(params, callback) {
    var ca = certs[params.message.message.caindex];
    if(ca) {
        smimelib.decrypt({ data: params.verified.data, cert: ca.channel.cert, key: ca.channel.key }, function(err, decrypt) {
            if(err) {
                callback(err, false);
            } else {
                //console.log(decrypt.toString());
                zlib.inflate(decrypt, function(err, buf) {
                    if(err) {
                        callback(err, false);
                    } else {
                        //console.log(buf.toString());
                        let vmsg = JSON.parse(buf.toString());
                        //let caindex = findCA(vmsg.request.ca);
                        //let ca = certs[caindex];
                        //console.log(message);
                        if(params.message.message.signtype=='csr') {
                            slotlib.signCSR({ publiccert: ca.base64, slotid: ca['token hexid'], csr: vmsg.request.csr, options: vmsg.request.options, module: ca.module, serial: ca['token serial'], pin: ca['token pin'], objectid: ca['ID']}, function(csrerr, signedcert) {
                                if(csrerr) {
                                    let signed = {
                                        success: false,
                                        siguuid: vmsg.siguuid,
                                        message: err
                                    }
                                    let unsigned = {
                                        type: 'signature response',
                                        siguuid: vmsg.siguuid,
                                        uuid: params.message.publisher
                                    }
                                    sendEncryptedMessage({publisher: params.message.publisher, channel: params.message.channel, signcert: ca, enccert: params.verified.certs[0], signed: JSON.stringify(signed), unsigned: unsigned}, function(err, resp) {
                                        if(err) {
                                            callback(err, false);
                                        } else {
                                            callback(csrerr, false);
                                        }
                                    });
                                } else {
                                    let signed = {
                                        success: true,
                                        siguuid: vmsg.siguuid,
                                        message: signedcert
                                    }
                                    let unsigned = {
                                        type: 'signature response',
                                        siguuid: vmsg.siguuid,
                                        uuid: params.message.publisher
                                    }
                                    sendEncryptedMessage({publisher: params.message.publisher, channel: params.message.channel, signcert: ca, enccert: params.verified.certs[0], signed: JSON.stringify(signed), unsigned: unsigned}, function(err, resp) {
                                        if(err) {
                                            //console.log(err);
                                            callback(err, false);
                                        } else {
                                            callback(false, false);
                                        }
                                    });
                                }
                            });
                        } else if(params.message.message.signtype=='crl') {
                            //console.log(params.message.message);
                            //console.log(vmsg);
                            slotlib.signCRL({ publiccert: ca.base64, slotid: ca['token hexid'], database: vmsg.request.database, days: vmsg.request.days, module: ca.module, serial: ca['token serial'], pin: ca['token pin'], objectid: ca['ID']}, function(crlerr, signedcrl) {
                                if(crlerr) {
                                    let signed = {
                                        success: false,
                                        siguuid: vmsg.siguuid,
                                        message: err
                                    }
                                    let unsigned = {
                                        type: 'signature response',
                                        siguuid: vmsg.siguuid,
                                        uuid: params.message.publisher
                                    }
                                    sendEncryptedMessage({publisher: params.message.publisher, channel: params.message.channel, signcert: ca, enccert: params.verified.certs[0], signed: JSON.stringify(signed), unsigned: unsigned}, function(err, resp) {
                                        if(err) {
                                            callback(err, false);
                                        } else {
                                            callback(crlerr, false);
                                        }
                                    });
                                } else {
                                    let signed = {
                                        success: true,
                                        siguuid: vmsg.siguuid,
                                        message: signedcrl
                                    }
                                    let unsigned = {
                                        type: 'signature response',
                                        siguuid: vmsg.siguuid,
                                        uuid: params.message.publisher
                                    }
                                    sendEncryptedMessage({publisher: params.message.publisher, channel: params.message.channel, signcert: ca, enccert: params.verified.certs[0], signed: JSON.stringify(signed), unsigned: unsigned}, function(err, resp) {
                                        if(err) {
                                            callback(err, false);
                                        } else {
                                            callback(false, false);
                                        }
                                    });
                                }
                            });
                        } else {
                            console.log('Unrecognized signtype');
                        }
                    }
                });
            }
        });
    } else {
        let signed = {
            success: false,
            siguuid: vmsg.siguuid,
            message: 'Failed to find CA on HSM'
        }
        let unsigned = {
            type: 'signature response',
            siguuid: vmsg.siguuid,
            uuid: params.message.publisher
        }
        sendEncryptedMessage({publisher: params.message.publisher, channel: params.message.channel, signcert: ca, enccert: params.verified.certs[0], signed: JSON.stringify(signed), unsigned: unsigned}, function(err, resp) {
            if(err) {
                callback(err, false);
            } else {
                callback('Failed to find CA on HSM', false);
            }
        });
    }
}

var queueRequest = function(params) {
    requests.push({params: params});
    if(busy===false) {
        processRequest();
    }
}

var processRequest = function() {
    busy = true;
    let request = requests.pop()

    let timeout = setTimeout(function() {
        console.log('CALLED REQUEST TIMEOUT. Request took more than 5 seconds. Allowing more requests...');
        if(requests.length > 0) {
            processRequest();
        } else {
            busy = false;
        }
    }, 5000);

    processSignature(request.params, function(err) {
        if(err) {
            console.log(err);
        } else {
            //console.log()
        }
        console.log('Remaining signature request queue length: ' + requests.length);
        clearTimeout(timeout);
        if(requests.length > 0) {
            processRequest();
        } else {
            busy = false;
        }
    });
}

var queueMessage = function(message) {
    let msgobj = {
        recvtime: moment(),
        message: message
    }
    messages.push(msgobj);
    if(busy===false) {
        processMessage();
    }
}

var processMessage = function() {
    busy = true;
    let message = messages.pop()

    let now = moment();
    //console.log(message.message.message);
    let expire = message.message.message.ttl || defaultttl;
    if(now.diff(message.recvtime, 'seconds') < expire) {
        let timeout = setTimeout(function() {
            console.log('CALLED MESSAGE TIMEOUT. Message took more than 5 seconds. Allowing more messages...');
            if(messages.length > 0) {
                processMessage();
            } else {
                busy = false;
            }
        }, 5000);

        messageReceived(message.message, function(err) {
            if(err) {
                console.log(err);
            } else {
                //console.log()
            }
            console.log('Remaining message queue length: ' + messages.length);
            clearTimeout(timeout);
            if(messages.length > 0) {
                processMessage();
            } else {
                busy = false;
            }
        });
    } else {
        console.log('Flushing queued message with expired TTL. Probably received too many requests : (');
        console.log('Remaining message queue length: ' + messages.length);
        if(messages.length > 0) {
            processMessage();
        } else {
            busy = false;
        }
    }
}

function messageReceived(message, callback) {
    //console.log(message);
    if(message.message.uuid == null || message.message.uuid==pubnub.getUUID()) {
        verifyMessage(message.message.smime, function(err, resp) {
            if(err) {
                //console.log(message);
                //console.log('Failed to verify message');
                callback(err, false);
            } else {
                //console.log(message);
                if(message.message.type=='solicit signature') {
                    console.log('Received a verified "' + message.message.type + '" message. Offerring services...');
                    let vmsg = JSON.parse(resp.data.toString());
                    //console.log(pubnub.getUUID());
                    let caindex = findCA(vmsg);
                    let ca = certs[caindex];
                    //console.log(caindex);
                    //console.log(ca);
                    let signed = {
                        uuid: pubnub.getUUID(),
                        caindex: caindex,
                        siguuid: vmsg.siguuid
                    }
                    let unsigned = {
                        type: 'services offerred',
                        uuid: message.publisher,
                        siguuid: vmsg.siguuid
                    }
                    sendSignedMessage({publisher: message.publisher, channel: message.channel, cert: ca, signed: JSON.stringify(signed), unsigned: unsigned}, function(err, resp) {
                        if(err) {
                            //console.log(resp);
                            callback(err, false);
                        } else {
                            //console.log(resp)
                            callback(false, resp);
                        }
                    });
                } else if(message.message.type=='signature request') {
                    //console.log(message);
                    console.log('Received a verified "' + message.message.type + '" message. Processing Signature...');
                    //queueRequest({verified: resp, message: message});
                    processSignature({verified: resp, message: message}, function(err) {
                        if(err) {
                            callback(err, false);
                        } else {
                            //console.log()
                            callback(false, false);
                        }
                    });
                } else {
                    console.log('ignoring unknown, verified pubnub message');
                    callback(false, false);
                }
            }
        });
    } else {
        //console.log('Message is not for me');
        callback(false, false);
    }
}

function request(params, callback) {
    var data = [];

    var req = https.request(params.options, function(res) {

        res.on('data', function(chunk) {
            data.push(chunk);
            //console.log(chunk.toString());
        });

        res.on('end', function(){
            //console.log(res.statusCode);
            //console.log(res.statusMessage);
            try {
                var responsebody = JSON.parse(new Buffer.concat(data).toString());
            } catch(e) {
                console.log('Invalid response from platform: ');
                console.log(new Buffer.concat(data).toString());
                callback('connection failure', false);
                return;
            }
            let response = {
                statusCode: res.statusCode,
                statusMessage: res.statusMessage,
                headers: res.headers,
                data: responsebody
            }
            //console.log(response);
            if(response.data.success==false) {
                callback(response.data.message, response);
            } else {
                callback(false, response);
            }
        });

        res.on('error', function(e){
            console.log('Failed to connect to platform: ');
            console.log(e.message);
            callback('connection failure', false);
        });
    });

    req.on('error', function(e){
        console.log('Failed to connect to platform: ');
        console.log(e.message);
        callback('connection failure', false);
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
        host: config.PLATFORMFQDN,
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
                                        //console.log(decrypt);
                                        callback(false, JSON.parse(decrypt.toString()));
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
            console.log(err);
            callback(err, false);
        } else {
            callback(false, request);
        }
    });
}

var getChannels = function(slots, certs, index, callback) {
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
                                if(err=='connection failure') {
                                    setTimeout(function() {
                                        console.log('trying again');
                                        connectPlatform(slots, callback);
                                    }, 60000);
                                } else {
                                    console.log(err);
                                    certs[index].channel.id = false;
                                    getChannels(slots, certs, index + 1, callback);
                                }
                            } else {
                                publishid = response.publishKey;
                                subscribeid = response.subscribeKey;
                                certs[index].channel.id = response.channel_id;
                                getChannels(slots, certs, index + 1, callback);
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
    certs = [];
    subscribeid = false;
    publishid = false;
    if(pubnub) {
        pubnub.unsubscribeAll();
    }
    for(let i = 0; i <= slots.length - 1; i++) {
        let slotids = Object.keys(slots[i].objects);
        for(let j = 0; j <= slotids.length - 1; j++) {
            //console.log(objects);
            let objects = Object.keys(slots[i].objects[slotids[j]]);
            for(let k = 0; k <= objects.length - 1; k++) {
                if(objects[k]=='Certificate Object') {
                    for(let l = 0; l <= slots[i].objects[slotids[j]][objects[k]].length - 1; l++) {
                        //console.log(slots[i].objects[slotids[j]][objects[k]][l].subject);
                        //if(slots[i].objects[slotids[j]][objects[k]][l].certinfo.attributes['Subject String'].indexOf('PIV Attestation') < 0) {
                        if(slots[i].objects[slotids[j]][objects[k]][l].label.indexOf('PIV Attestation') < 0) {
                            let cert = Object.assign({}, slots[i].objects[slotids[j]][objects[k]][l]);
                            cert['token serial'] = slots[i]['serial num'];
                            cert['token hexid'] = slots[i]['hexid'];
                            cert['token id'] = slots[i]['id'];
                            cert['token label'] = slots[i]['token label'];
                            cert['token pin'] = config.USERPIN;
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

var connectPlatform = function(slots, callback) {
    connectSlots(slots, function(err, certs) {
        if(err) {
            callback(err);
        } else {
            //console.log(certs);
            getChannels(slots, certs, false, function(err) {
                if(err) {
                    //console.log(err);
                    callback(err, false);
                } else {
                    //console.log(certs);
                    //callback(false, certs);
                    let channels = [];
                    for (let i = 0; i <= certs.length - 1; i++) {
                        if(certs[i].channel.id) {
                            channels.push(certs[i].channel.id);
                        }
                    }
                    //console.log(channels);
                    if(subscribeid && publishid) {
                        if(pubnub) {
                            pubnub.subscribe({channels: channels});
                            callback(false, false);
                        } else {
                            pubnub = new pubnublib({subscribeKey: subscribeid, publishKey: publishid, channels: channels});
                            pubnub.event.on('message', function(message) {
                                //messageReceived(message);
                                queueMessage(message);
                            });
                            callback(false, false);
                        }
                    } else {
                        callback('Unable to connect certificate to ' + config.PLATFORMFQDN, false);
                    }
                }
            });
        }
    });
}

module.exports = {
    connectSlots: function(slots, callback) {
        connectPlatform(slots, function(err, certs) {
            if(err) {
                console.log(err);
            } else {
                console.log('Finished attempting to connect supported certificates to ' + config.PLATFORMFQDN + '...');
            }
        });
    }
}