const smimelib = require('./smime/index');
const slotlib = require('./slotlib');
const pubnublib = require('./pubnub');
const https = require('https');
var zlib = require('zlib');

var pubnub = false;

var certs = [];
var subscribeid = false;
var publishid = false;

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

function messageReceived(message) {
    //console.log(message);
    verifyMessage(message.message.smime, function(err, resp) {
        if(err) {
            //console.log(message);
            console.log('Failed to verify message');
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
                    caindex: caindex
                }
                let unsigned = {
                    type: 'services offerred'
                }
                sendSignedMessage({publisher: message.publisher, channel: message.channel, cert: ca, signed: JSON.stringify(signed), unsigned: unsigned}, function(err, resp) {
                    if(err) {
                        console.log(resp);
                    } else {
                        //console.log(resp)
                    }
                });
            } else if(message.message.type=='signature request') {
                //console.log(message);
                console.log('Received a verified "' + message.message.type + '" message. Processing Signature...');
                var ca = certs[message.message.caindex];
                if(ca) {
                    smimelib.decrypt({ data: resp.data, cert: ca.channel.cert, key: ca.channel.key }, function(err, decrypt) {
                        if(err) {
                            console.log(err);
                            //callback(err, false);
                        } else {
                            //console.log(decrypt.toString());
                            zlib.inflate(decrypt, function(err, buf) {
                                if(err) {
                                    console.log('failed to inflate');
                                    console.log(err);
                                } else {
                                    //console.log(buf.toString());
                                    let vmsg = JSON.parse(buf.toString());
                                    if(vmsg.uuid==pubnub.getUUID()) {
                                        //let caindex = findCA(vmsg.request.ca);
                                        //let ca = certs[caindex];
                                        //console.log(message);
                                        if(message.message.signtype=='csr') {
                                            slotlib.signCSR({ publiccert: ca.base64, slotid: ca['token hexid'], csr: vmsg.request.csr, options: vmsg.request.options, module: ca.module, serial: ca['token serial'], pin: ca['token pin'], objectid: ca['ID']}, function(err, signedcert) {
                                                if(err) {
                                                    let signed = {
                                                        success: false,
                                                        siguuid: vmsg.siguuid,
                                                        message: err
                                                    }
                                                    let unsigned = {
                                                        type: 'signature response'
                                                    }
                                                    sendEncryptedMessage({publisher: message.publisher, channel: message.channel, signcert: ca, enccert: resp.certs[0], signed: JSON.stringify(signed), unsigned: unsigned}, function(err, resp) {
                                                        if(err) {
                                                            //console.log(err);
                                                            console.log(resp);
                                                        } else {
                                                            //console.log(resp)
                                                        }
                                                    });
                                                } else {
                                                    let signed = {
                                                        success: true,
                                                        siguuid: vmsg.siguuid,
                                                        message: signedcert
                                                    }
                                                    let unsigned = {
                                                        type: 'signature response'
                                                    }
                                                    sendEncryptedMessage({publisher: message.publisher, channel: message.channel, signcert: ca, enccert: resp.certs[0], signed: JSON.stringify(signed), unsigned: unsigned}, function(err, resp) {
                                                        if(err) {
                                                            //console.log(err);
                                                            console.log(resp);
                                                        } else {
                                                            //console.log(resp)
                                                        }
                                                    });
                                                }
                                            });
                                        } else if(message.message.signtype=='crl') {
                                            //console.log(message.message);
                                            //console.log(vmsg);
                                            slotlib.signCRL({ publiccert: ca.base64, slotid: ca['token hexid'], database: vmsg.request.database, days: vmsg.request.days, module: ca.module, serial: ca['token serial'], pin: ca['token pin'], objectid: ca['ID']}, function(err, signedcrl) {
                                                if(err) {
                                                    let signed = {
                                                        success: false,
                                                        siguuid: vmsg.siguuid,
                                                        message: err
                                                    }
                                                    let unsigned = {
                                                        type: 'signature response'
                                                    }
                                                    sendEncryptedMessage({publisher: message.publisher, channel: message.channel, signcert: ca, enccert: resp.certs[0], signed: JSON.stringify(signed), unsigned: unsigned}, function(err, resp) {
                                                        if(err) {
                                                            //console.log(err);
                                                            console.log(resp);
                                                        } else {
                                                            //console.log(resp)
                                                        }
                                                    });
                                                } else {
                                                    let signed = {
                                                        success: true,
                                                        siguuid: vmsg.siguuid,
                                                        message: signedcrl
                                                    }
                                                    let unsigned = {
                                                        type: 'signature response'
                                                    }
                                                    sendEncryptedMessage({publisher: message.publisher, channel: message.channel, signcert: ca, enccert: resp.certs[0], signed: JSON.stringify(signed), unsigned: unsigned}, function(err, resp) {
                                                        if(err) {
                                                            //console.log(err);
                                                            console.log(resp);
                                                        } else {
                                                            //console.log(resp)
                                                        }
                                                    });
                                                }
                                            });
                                        } else {
                                            console.log('Unrecognized signtype');
                                        }
                                    } else {
                                        console.log('Signing request is not for me');
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
                        type: 'signature response'
                    }
                    sendEncryptedMessage({publisher: message.publisher, channel: message.channel, signcert: ca, enccert: resp.certs[0], signed: JSON.stringify(signed), unsigned: unsigned}, function(err, resp) {
                        if(err) {
                            //console.log(err);
                            console.log(resp);
                        } else {
                            console.log(resp)
                        }
                    });
                }
            } else {
                console.log('ignoring unknown, verified pubnub message');
            }
        }
    })
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

                        /*for (let i = 0; i <= certs.length - 1; i++) {
                            if(certs[i].channel.id) {
                                pubnub.sendMessage({meta: '{"uuid": "pn-0f0aca1e-7641-41ce-9872-9053adb8ee4"}', channel: certs[i].channel.id, message: "test"}, function(status, response) {
                                    if(status.error) {
                                        callback(status.error, status);
                                    } else {
                                        callback(false, response);
                                    }
                                });
                            }
                        }*/
                    }
                });
                //callback(certs);
            }
        });
    }
}