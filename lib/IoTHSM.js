const smimelib = require('./smime/index');
const openssl2 = require('./openssl2');
const slotlib = require('./slotlib');
const pubnublib = require('./pubnub');
const statelib = require('./statelib');
const common = require('./common');
var zlib = require('zlib');
const crypto = require('crypto');
var config = require('../config');
var pinlib = require('../lib/pin');
var queues = {};
var pubnub = false;
var certs = [];
var subscribeid = false;
var publishid = false;
var moment = require('moment');
const defaultttl = 5;
var badpin = {};
var seenrequests = {};
var renewtimers = [];
var lastmessage = 0;

const smimeformat = 'SMIME';
//the platform signs its messages with a certificate with this common name; the message CA could issue certificates to others
const platformsigner = 'PKIaaS.io SMIME Certificate';

var checkPlatformSigner = function(signercert) {
    let signer;
    try {
        signer = new crypto.X509Certificate(signercert);
    } catch(e) {
        return 'Unable to read the message signer certificate';
    }
    let cn = signer.subject.split('\n').filter(function(line) { return line.indexOf('CN=') == 0; });
    if(cn.length != 1 || cn[0] != 'CN=' + platformsigner || !signer.keyUsage || signer.keyUsage.indexOf('1.3.6.1.5.5.7.3.4') < 0) {
        return 'Message was not signed by the ' + config.PLATFORMFQDN + ' signing certificate';
    }
    return false;
}

var verifyMessage = function(message, callback) {
    smimelib.x509.getCACert(function(err, ca) {
        if(err) {
            console.log(err);
            callback(err, false);
        } else {
            openssl2.smime.verify({format: smimeformat, ca: ca, data: message}, function(err, verify) {
            // smimelib.verify({ca: ca, smime: message}, function(err, verify) {
                if(err) {
                    console.log(err);
                    callback(err, false);
                } else {
                    let signererr = checkPlatformSigner(verify.signercert);
                    if(signererr) {
                        console.log(signererr);
                        callback(signererr, false);
                    } else {
                        callback(false, verify);
                    }
                }
            });
        }
    });
}

var encryptMessage = function(params, callback) {
    let input = Buffer.from(params.signed, 'utf8');
    zlib.deflate(input, function(err, buf) {
        if(err) {
            callback(err, false);
        } else {
            openssl2.smime.encrypt({format: smimeformat, cert: params.enccert, data: buf}, function(err, smimeenc) {
            // smimelib.encrypt({cert: params.enccert, data: buf}, function(err, smimeenc) {
                if(err) {
                    callback(err, false);
                } else {
                    callback(err, smimeenc.data);
                }
            });
        }
    });
}

var sendEncryptedMessage = function(params, callback) {
    encryptMessage(params, function(err, smimeenc) {
        if(err) {
            callback(err, false);
        } else {
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

var signMessage = function(params, callback) {
    smimelib.x509.getCert(params.cert, function(err, newcert) {
        if(err) {
            callback(err, false);
        } else {
            //cert.channel.cert = newcert;
            openssl2.smime.sign({format: smimeformat, cert: newcert, key: params.cert.channel.key.base64, password: params.cert.channel.key.pass, data: params.signed}, function(err, smimesign) {
            // smimelib.sign({cert: newcert, key: params.cert.channel.key, data: params.signed}, function(err, smimesign) {
                if(err) {
                    callback(err, false);
                } else {
                    callback(false, smimesign.data);
                }
            });
        }
    });
}

var sendSignedMessage = function(params, callback) {
    signMessage(params, function(err, smimesign) {
        if(err) {
            callback(err, false);
        } else {
            params.unsigned.smime = smimesign
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

function findCA(ca) {
    for(let i = 0; i <= certs.length - 1; i++) {
        if(ca.serial==certs[i].certinfo.attributes['Serial Number'].split(':').join('').toLowerCase() && ca.thumbprint==certs[i].certinfo.attributes['Thumbprint'].split(':').join('').toLowerCase()) {
            return i;
        }
    }
    return -1;
}

//a signature request is encrypted to a channel key that is replaced at least once per channel certificate lifetime, so remembering request IDs for longer than that stops a captured request from being replayed
var isReplay = function(siguuid) {
    let now = Date.now();
    for(let id in seenrequests) {
        if(now - seenrequests[id] > (smimelib.x509.lifetime + 60) * 60 * 1000) {
            delete seenrequests[id];
        }
    }
    if(!siguuid || seenrequests[siguuid]) {
        return true;
    }
    seenrequests[siguuid] = now;
    return false;
}

//the platform encrypts to the certificate in the services offer, which may be the previous one if the channel key was renewed in between
var decryptChannel = function(channel, data, callback) {
    openssl2.smime.decrypt({format: smimeformat, data: data, cert: channel.cert, key: channel.key.base64, password: channel.key.pass }, function(err, decrypt) {
        if(err && channel.previous && Date.now() < channel.previous.until) {
            openssl2.smime.decrypt({format: smimeformat, data: data, cert: channel.previous.cert, key: channel.previous.key.base64, password: channel.previous.key.pass }, function(preverr, prevdecrypt) {
                if(preverr) {
                    callback(err, false);
                } else {
                    console.log('Decrypted a signature request with the previous channel key');
                    callback(false, prevdecrypt);
                }
            });
        } else {
            callback(err, decrypt);
        }
    });
}

function processSignature(params, callback) {
    var ca = certs[params.message.message.caindex];
    if(ca) {
        decryptChannel(ca.channel, params.verified.data, function(err, decrypt) {
        // smimelib.decrypt({ data: params.verified.data, cert: ca.channel.cert, key: ca.channel.key }, function(err, decrypt) {
            if(err) {
                callback(err, false);
            } else {
                //console.log(decrypt.toString());
                zlib.inflate(decrypt.data, function(err, buf) {
                    if(err) {
                        callback(err, false);
                    } else {
                        pinlib.getPins({serial: ca['token serial']},function(err, pins) {
                            if(err) {
                                callback('Failed to get pins', false);
                            } else {
                                //console.log(pins);
                                let userpin;
                                if(pins) {
                                    userpin = pins.USERPIN;
                                } else {
                                    userpin = config.USERPIN;
                                }
                                //console.log(buf.toString());
                                let vmsg = JSON.parse(buf.toString());
                                if(isReplay(vmsg.siguuid)) {
                                    callback('Ignoring a signature request that was already processed', false);
                                    return;
                                }
                                //let caindex = findCA(vmsg.request.ca);
                                //let ca = certs[caindex];
                                //console.log(message);
                                if(params.message.message.signtype=='csr') {
                                    slotlib.signCSR({ publiccert: ca.base64, slotid: ca['token hexid'], csr: vmsg.request.csr, options: vmsg.request.options, module: ca.module, serial: ca['token serial'], pin: userpin, objectid: ca['ID']}, function(csrerr, signedcert) {
                                        if(csrerr) {
                                            let signed = {
                                                success: false,
                                                siguuid: vmsg.siguuid,
                                                message: csrerr
                                            }
                                            let unsigned = {
                                                type: 'signature response',
                                                siguuid: vmsg.siguuid,
                                                uuid: params.message.publisher
                                            }
                                            sendEncryptedMessage({publisher: params.message.publisher, channel: params.message.channel, signcert: ca, enccert: params.verified.signercert, signed: JSON.stringify(signed), unsigned: unsigned}, function(err, resp) {
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
                                            sendEncryptedMessage({publisher: params.message.publisher, channel: params.message.channel, signcert: ca, enccert: params.verified.signercert, signed: JSON.stringify(signed), unsigned: unsigned}, function(err, resp) {
                                                if(err) {
                                                    //console.log(err);
                                                    callback(err, false);
                                                } else {
                                                    callback(false, false);
                                                }
                                            });
                                        }
                                    });
                                } else if(params.message.message.signtype=='cms') {
                                    // console.log(JSON.stringify(vmsg, null, 2));
                                    slotlib.signCMS({
                                        inform: vmsg.request.options.inform,
                                        outform: vmsg.request.options.outform,
                                        publiccert: ca.base64,
                                        // key: senderrsa.data,
                                        data: vmsg.request.options.data,
                                        encoding: vmsg.request.options.encoding,
                                        addcerts: vmsg.request.options.addcerts,
                                        module: ca.module,
                                        serial: ca['token serial'],
                                        pin: userpin,
                                        smimecap: vmsg.request.options.smimecap,
                                        contenttype: vmsg.request.options.contenttype,
                                        objectid: ca['ID']
                                    }, function(cmserr, signedcms) {
                                        if(cmserr) {
                                            let signed = {
                                                success: false,
                                                siguuid: vmsg.siguuid,
                                                message: cmserr
                                            }
                                            let unsigned = {
                                                type: 'signature response',
                                                siguuid: vmsg.siguuid,
                                                uuid: params.message.publisher
                                            }
                                            sendEncryptedMessage({publisher: params.message.publisher, channel: params.message.channel, signcert: ca, enccert: params.verified.signercert, signed: JSON.stringify(signed), unsigned: unsigned}, function(err, resp) {
                                                if(err) {
                                                    callback(err, false);
                                                } else {
                                                    callback(cmserr, false);
                                                }
                                            });
                                        } else {
                                            let signed = {
                                                success: true,
                                                siguuid: vmsg.siguuid,
                                                message: signedcms
                                            }
                                            let unsigned = {
                                                type: 'signature response',
                                                siguuid: vmsg.siguuid,
                                                uuid: params.message.publisher
                                            }
                                            sendEncryptedMessage({publisher: params.message.publisher, channel: params.message.channel, signcert: ca, enccert: params.verified.signercert, signed: JSON.stringify(signed), unsigned: unsigned}, function(err, resp) {
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
                                    //console.log(vmsg);
                                    let signed = {
                                        success: false,
                                        siguuid: vmsg.siguuid,
                                        message: null
                                    }
                                    let unsigned = {
                                        type: 'signature response',
                                        siguuid: vmsg.siguuid,
                                        uuid: params.message.publisher
                                    }
                                    pinlib.getPins({serial: ca['token serial']},function(err, pins) {
                                        if(err) {
                                            callback('Failed to get pins', false);
                                        } else {
                                            //console.log(pins);
                                            let userpin;
                                            if(pins) {
                                                userpin = pins.USERPIN;
                                            } else {
                                                userpin = config.USERPIN;
                                            }
                                            slotlib.signCRL({ publiccert: ca.base64, slotid: ca['token hexid'], database: vmsg.request.database, days: vmsg.request.days, module: ca.module, serial: ca['token serial'], pin: userpin, objectid: ca['ID']}, function(crlerr, signedcrl) {
                                                if(crlerr) {
                                                    signed.message = crlerr;
                                                    sendEncryptedMessage({publisher: params.message.publisher, channel: params.message.channel, signcert: ca, enccert: params.verified.signercert, signed: JSON.stringify(signed), unsigned: unsigned}, function(err, resp) {
                                                        if(err) {
                                                            callback(err, false);
                                                        } else {
                                                            callback(crlerr, false);
                                                        }
                                                    });
                                                } else {
                                                    //console.log(signedcrl);
                                                    signed.message = signedcrl;
                                                    let serial = ca.certinfo.attributes['Serial Number'].toLowerCase().split(':').join('');
                                                    let thumbprint = ca.certinfo.attributes['Thumbprint'].toLowerCase().split(':').join('');
                                                    var options = {
                                                        host: config.PLATFORMFQDN,
                                                        port: 443,
                                                        path: '/api/public/delivercrl/' + serial + '/' + thumbprint,
                                                        method: 'POST',
                                                        headers: {
                                                            'Content-Type': 'application/json'
                                                        }
                                                    }
                                                    encryptMessage({enccert: params.verified.signercert, signed: JSON.stringify(signed)}, function(err, smimeenc) {
                                                        if(err) {
                                                            signed.message = err;
                                                            sendEncryptedMessage({publisher: params.message.publisher, channel: params.message.channel, signcert: ca, enccert: params.verified.signercert, signed: JSON.stringify(signed), unsigned: unsigned}, function(err, resp) {
                                                                if(err) {
                                                                    callback(err, false);
                                                                } else {
                                                                    callback(false, false);
                                                                }
                                                            });
                                                        } else {
                                                            signMessage({cert: ca, signed: smimeenc}, function(err, smimesign) {
                                                                if(err) {
                                                                    signed.message = err;
                                                                    sendEncryptedMessage({publisher: params.message.publisher, channel: params.message.channel, signcert: ca, enccert: params.verified.signercert, signed: JSON.stringify(signed), unsigned: unsigned}, function(err, resp) {
                                                                        if(err) {
                                                                            callback(err, false);
                                                                        } else {
                                                                            callback(false, false);
                                                                        }
                                                                    });
                                                                } else {
                                                                    common.request({options: options, body: JSON.stringify({smime: smimesign})}, function(err, resp) {
                                                                        if(err) {
                                                                            signed.message = err;
                                                                            sendEncryptedMessage({publisher: params.message.publisher, channel: params.message.channel, signcert: ca, enccert: params.verified.signercert, signed: JSON.stringify(signed), unsigned: unsigned}, function(err, resp) {
                                                                                if(err) {
                                                                                    callback(err, false);
                                                                                } else {
                                                                                    callback(false, false);
                                                                                }
                                                                            });
                                                                        } else {
                                                                            signed.message = 'crl uploaded';
                                                                            signed.success = true;
                                                                            sendEncryptedMessage({publisher: params.message.publisher, channel: params.message.channel, signcert: ca, enccert: params.verified.signercert, signed: JSON.stringify(signed), unsigned: unsigned}, function(err, resp) {
                                                                                if(err) {
                                                                                    callback(err, false);
                                                                                } else {
                                                                                    callback(false, false);
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
                                    });
                                } else {
                                    console.log('Unrecognized signtype');
                                }
                            }
                        });
                    }
                });
            }
        });
    } else {
        //without the CA there's no key to decrypt the request or sign a response with, so the platform's request times out
        callback('Failed to find CA on HSM for signature request ' + params.message.message.caindex, false);
    }
}

//a YubiKey signs one request at a time; Google KMS and SoftHSM can sign several at once
var getConcurrency = function(module) {
    let lib = module.split('/').at(-1);
    if(lib == 'libkmsp11.so') {
        return parseInt(config.KMSCONCURRENCY) || 4;
    } else if(lib == 'libsofthsm2.so') {
        return parseInt(config.SOFTHSMCONCURRENCY) || 2;
    } else {
        return 1;
    }
}

//each token has its own queue, so a slow token doesn't hold up the others
var getQueue = function(cert) {
    let id = cert.module + ' ' + cert['token serial'];
    if(!queues.hasOwnProperty(id)) {
        queues[id] = {
            running: 0,
            limit: getConcurrency(cert.module),
            tasks: []
        }
    }
    return queues[id];
}

//tasks that use the token wait in its queue, first in first out; a task with an expiry time is dropped if it's still waiting then
var queueTask = function(cert, task, expires) {
    let queue = getQueue(cert);
    queue.tasks.push({
        expires: expires || Infinity,
        task: task
    });
    processQueue(queue);
}

var processQueue = function(queue) {
    while(queue.running < queue.limit && queue.tasks.length > 0) {
        let next = queue.tasks.shift();
        if(Date.now() >= next.expires) {
            console.log('Flushing queued message with expired TTL. Probably received too many requests : (');
            console.log('Remaining message queue length: ' + queue.tasks.length);
            continue;
        }
        queue.running++;
        //whichever finishes first, the timeout or the task, moves the queue on
        let finished = false;
        let done = function() {
            if(finished) {
                return;
            }
            finished = true;
            queue.running--;
            console.log('Remaining message queue length: ' + queue.tasks.length);
            processQueue(queue);
        }
        let timeout = setTimeout(function() {
            console.log('CALLED MESSAGE TIMEOUT. Message took more than 5 seconds. Allowing more messages...');
            done();
        }, 5000);
        next.task(function(err) {
            if(err) {
                console.log(err);
            }
            clearTimeout(timeout);
            done();
        });
    }
}

//renew channel certificates halfway through their remaining lifetime, so a request never waits for a renewal on the HSM
var scheduleRenewal = function(cert, delay) {
    if(delay === undefined) {
        delay = Math.max(moment(cert.channel.certinfo.attributes['Not After']).diff(moment()) / 2, 60 * 1000);
    }
    delay = Math.min(delay, 2147483647);
    let timer = setTimeout(function() {
        renewtimers.splice(renewtimers.indexOf(timer), 1);
        queueTask(cert, function(callback) {
            //the slots were reloaded since this was scheduled
            if(certs.indexOf(cert) < 0) {
                callback(false);
                return;
            }
            //a renewal between a services offer and its signature request would delay the signature past the platform's timeout,
            //so wait for a quiet moment unless the certificate is getting close to expiring
            if(Date.now() - lastmessage < 10 * 1000 && moment(cert.channel.certinfo.attributes['Not After']).diff(moment(), 'minutes') > Math.max(smimelib.x509.lifetime / 4, 10)) {
                scheduleRenewal(cert, 15 * 1000);
                callback(false);
                return;
            }
            console.log(new Date + ' - Renewing the channel certificate for ' + cert.label + ' on token serial ' + cert['token serial'] + '...');
            smimelib.x509.renewCert(cert, function(err) {
                if(certs.indexOf(cert) < 0) {
                    callback(false);
                } else if(err) {
                    if(String(err).indexOf('Login failed') >= 0) {
                        //retrying a wrong PIN would block it on the token
                        badpin[cert['token serial']] = true;
                        cert.channel.message = 'Invalid PIN';
                        callback('Failed to renew the channel certificate for ' + cert.label + ': invalid PIN for token serial ' + cert['token serial'] + '. Not retrying until the slots are reloaded.');
                    } else {
                        scheduleRenewal(cert, 5 * 60 * 1000);
                        callback('Failed to renew the channel certificate for ' + cert.label + ', trying again in 5 minutes: ' + err);
                    }
                } else {
                    console.log('Renewed the channel certificate for ' + cert.label + ', valid until ' + cert.channel.certinfo.attributes['Not After']);
                    scheduleRenewal(cert);
                    callback(false);
                }
            });
        });
    }, delay);
    renewtimers.push(timer);
}

//offers and the checks before a signature don't use the HSM, so they happen right away instead of waiting behind signatures
function messageReceived(message, callback) {
    //console.log(message);
    let recvtime = Date.now();
    lastmessage = recvtime;
    let expires = recvtime + (message.message.ttl || defaultttl) * 1000;
    if(message.message.uuid == null || message.message.uuid==pubnub.getUUID()) {
        verifyMessage(message.message.smime, function(err, resp) {
            if(err) {
                //console.log(message);
                //console.log('Failed to verify message');
                callback(err, false);
            } else {
                //console.log(message);
                if(message.message.type=='solicit signature') {
                    console.log(new Date + ' - Received a verified "' + message.message.type + '" message. Offerring services...');
                    let vmsg = JSON.parse(resp.data.toString());
                    //console.log(pubnub.getUUID());
                    let caindex = findCA(vmsg);
                    let ca = certs[caindex];
                    //console.log(caindex);
                    //console.log(ca);
                    if(!ca) {
                        console.log('This HSM does not have the requested CA. Not offering services.');
                        callback(false, false);
                        return;
                    }
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
                    let offer = function(callback) {
                        sendSignedMessage({publisher: message.publisher, channel: message.channel, cert: ca, signed: JSON.stringify(signed), unsigned: unsigned}, function(err, resp) {
                            if(err) {
                                //console.log(resp);
                                callback(err, false);
                            } else {
                                //console.log(resp)
                                callback(false, resp);
                            }
                        });
                    }
                    if(smimelib.x509.isCurrent(ca)) {
                        offer(callback);
                    } else {
                        //signing the offer renews the channel certificate on the token first
                        queueTask(ca, offer, expires);
                        callback(false, false);
                    }
                } else if(message.message.type=='signature request') {
                    //console.log(message);
                    let ca = certs[message.message.caindex];
                    if(!ca) {
                        //without the CA there's no key to decrypt the request or sign a response with, so the platform's request times out
                        callback('Failed to find CA on HSM for signature request ' + message.message.caindex, false);
                        return;
                    }
                    console.log(new Date + ' - Received a verified "' + message.message.type + '" message. Queueing the signature...');
                    queueTask(ca, function(callback) {
                        console.log(new Date + ' - Processing Signature...');
                        processSignature({verified: resp, message: message}, callback);
                    }, expires);
                    callback(false, false);
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

var sendRequest = function(cert, params, callback) {
    var options = {
        host: config.PLATFORMFQDN,
        port: 443,
        path: '/api/public/getiotconnectiondata',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    }

    // console.log(params);

    common.request({options: options, body: JSON.stringify(params)}, function(err, resp) {
        if(err) {
            callback(err, resp);
        } else {
            if(resp.data.success) {
                smimelib.x509.getCACert(function(err, ca) {
                    if(err) {
                        console.log(err);
                        callback(err, false);
                    } else {
                        openssl2.smime.verify({format: smimeformat, ca: ca, data: resp.data.data}, function(err, verify) {
                        // smimelib.verify({ca: ca, smime: resp.data.data}, function(err, verify) {
                            if(err) {
                                console.log(err);
                                callback(err, false);
                            } else if(checkPlatformSigner(verify.signercert)) {
                                callback(checkPlatformSigner(verify.signercert), false);
                            } else {
                                openssl2.smime.decrypt({format: smimeformat, data: verify.data, cert: cert.channel.cert, key: cert.channel.key.base64, password: cert.channel.key.pass }, function(err, decrypt) {
                                // smimelib.decrypt({ data: verify.data, cert: cert.channel.cert, key: cert.channel.key }, function(err, decrypt) {
                                    if(err) {
                                        console.log(err);
                                        callback(err, false);
                                    } else {
                                        callback(false, JSON.parse(decrypt.data.toString()));
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
    // console.log(cert);
    openssl2.smime.sign({format: smimeformat, cert: issued, key: cert.channel.key.base64, password: cert.channel.key.pass, data: JSON.stringify(jsonrequest)}, function(err, smimesign) {
    // smimelib.sign({ data: JSON.stringify(jsonrequest), cert: issued, key: cert.channel.key }, function(err, request) {
        if(err) {
            console.log(err);
            callback(err, false);
        } else {
            callback(false, smimesign.data);
        }
    });
}

var getChannels = function(slots, certs, index, callback) {
    if(index===null || index===false) {
        index = 0;
    }
    if(index <= certs.length - 1) {
        //console.log(certs[index]);
        if(badpin[certs[index]['token serial']]) {
            certs[index].channel.message = 'Invalid PIN';
            certs[index].channel.id = false;
            getChannels(slots, certs, index + 1, callback);
        } else {
            smimelib.x509.getCert(certs[index], function(err, cert) {
                if(err) {
                    if(err.indexOf('Login failed') >= 0) {
                        badpin[certs[index]['token serial']] = true;
                        console.log('Invalid PIN for token serial ' + certs[index]['token serial']);
                        certs[index].channel.message = 'Invalid PIN';
                        certs[index].channel.id = false;
                        getChannels(slots, certs, index + 1, callback);
                    } else {
                        console.log(err);
                        // console.log('---------------------------');
                        certs[index].channel.message = err;
                        certs[index].channel.id = false;
                        getChannels(slots, certs, index + 1, callback);
                    }
                } else {
                    certs[index].channel.id = null;
                    certs[index].channel.cert = cert;
                    let jsonrequest = {
                        serial: certs[index].certinfo.attributes['Serial Number'].toLowerCase().split(':').join(''),
                        thumbprint: certs[index].certinfo.attributes['Thumbprint'].toLowerCase().split(':').join('')
                    }
                    createRequest(jsonrequest, certs[index], cert, function(err, request) {
                        if(err) {
                            console.log(err);
                            certs[index].channel.message = err;
                            certs[index].channel.id = false;
                            getChannels(slots, certs, index + 1, callback);
                        } else {
                            //callback(false, request);
                            jsonrequest.smime = request;
                            //console.log(request);
                            sendRequest(certs[index], jsonrequest, function(err, response) {
                                if(err) {
                                    if(err=='connection failure') {
                                        certs[index].channel.message = response + ' (trying again after timeout)';
                                        setTimeout(function() {
                                            console.log('trying again');
                                            connectPlatform(slots, callback);
                                        }, 60000);
                                    } else {
                                        console.log(err);
                                        certs[index].channel.message = err;
                                        certs[index].channel.id = false;
                                        getChannels(slots, certs, index + 1, callback);
                                    }
                                } else {
                                    publishid = response.publishKey;
                                    subscribeid = response.subscribeKey;
                                    certs[index].channel.id = response.channel_id;
                                    scheduleRenewal(certs[index]);
                                    getChannels(slots, certs, index + 1, callback);
                                }
                            });
                        }
                    });
                }
            });
        }
    } else {
        callback(false, certs);
    }
}

var connectSlots = function(slots, callback) {
    for(let i = 0; i <= renewtimers.length - 1; i++) {
        clearTimeout(renewtimers[i]);
    }
    renewtimers = [];
    badpin = {};
    certs = [];
    //tasks already running finish, but nothing waiting starts with the old slots
    for(let id in queues) {
        queues[id].tasks = [];
    }
    queues = {};
    subscribeid = false;
    publishid = false;
    if(pubnub) {
        pubnub.unsubscribeAll();
    }
    let state = statelib.get();
    // console.log(state);
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
                            //cert['token pin'] = config.USERPIN;
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
                    callback(err);
                } else {
                    //console.log(certs);
                    //callback(false);
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
                            callback(false);
                        } else {
                            pubnub = new pubnublib({subscribeKey: subscribeid, publishKey: publishid, channels: channels});
                            pubnub.event.on('message', function(message) {
                                messageReceived(message, function(err) {
                                    if(err) {
                                        console.log(err);
                                    }
                                });
                            });
                            callback(false);
                        }
                    } else {
                        callback('Unable to connect certificate to ' + config.PLATFORMFQDN);
                    }
                }
            });
        }
    });
}

module.exports = {
    connectSlots: function(slots, callback) {
        connectPlatform(slots, function(err) {
            if(err) {
                console.log(err);
            } else {
                //console.log(certs);
                console.log('Finished attempting to connect supported certificates to ' + config.PLATFORMFQDN + '...');
            }
        });
    },
    getSlots: function() {
        let iot = {
            connected: 0,
            hsm: {}
        };
        //console.log(certs);
        for(let i = 0; i <= certs.length - 1; i++) {
            if(!iot.hsm.hasOwnProperty(certs[i]['token serial'])) {
                iot.hsm[certs[i]['token serial']] = {};
            }
            let id = certs[i].ID;
            // console.log(certs[i]);
            if(!id || id.length > 100) {
                id = certs[i].label;
            }
            iot.hsm[certs[i]['token serial']][id] = { connected: false }
            if(certs[i].channel.id) {
                iot.hsm[certs[i]['token serial']][id].connected = true;
                iot.connected++;
            } else {
                iot.hsm[certs[i]['token serial']][id].message = certs[i].channel.message
            }
        }
        return iot;
    }
}