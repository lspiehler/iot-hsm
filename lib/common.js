const https = require('https');
const http = require('http');

const protocols = {
    http: http,
    https: https
}

const hashAlgMapping = {
    'SHA256-RSA-PKCS-PSS': 'sha256',
    'SHA512-RSA-PKCS': 'sha512',
    'ECDSA-SHA256': 'sha256',
    'ECDSA-SHA512': 'sha512',
    'ECDSA-SHA384': 'sha384'
};


module.exports = {
    moduleURIParam: function(module) {
        let moduleMap = {
            '/usr/lib/softhsm/libsofthsm2.so': {
                param: 'id',
                prefix: '%'
            },
            '/usr/lib/x86_64-linux-gnu/libykcs11.so': {
                param: 'id',
                prefix: '%'
            },
            '/usr/lib/kms/libkmsp11.so': {
                param: 'object',
                prefix: ''
            }
        };
        return moduleMap[module] || {id: 'id', prefix: '%'};
    },
    getAllowedHashAlg: function(key) {
        if(key.hasOwnProperty('Allowed mechanisms')) {
            let mechanisms = key['Allowed mechanisms'].split(',');
            for(let i = 0; i <= mechanisms.length - 1; i++) {
                if(hashAlgMapping.hasOwnProperty(mechanisms[i])) {
                    // console.log(hashAlgMapping[mechanisms[i]]);
                    return hashAlgMapping[mechanisms[i]];
                }
            }
        }
        return 'sha256';
    },
    getSlotIndex: function(slots, serial) {
        for(let i = 0; i <= slots.slots.length - 1; i++) {
            //console.log(serial);
            //console.log(slots.slots[i]['serial num']);
            if(slots.slots[i]['serial num']==serial) {
                return i;
            }
        }
        return -1;
    },
    getTokenType: function(slot) {
        //console.log('here');
        //console.log(slot);
        if(slot.modulePath.split('/').at(-1)=='libkmsp11.so') {
            return 'google';
        } else if(slot.modulePath.split('/').at(-1)=='libykcs11.so') {
            return 'yubikey';
        } else if(slot.modulePath.split('/').at(-1)=='libsofthsm2.so') {
            return 'softhsm';
        } else {
            return 'unknown';
        }
    },
    request: function(params, callback) {
        let protocol = 'https';
        if(params.hasOwnProperty('protocol')) {
            protocol = params.protocol;
        }
        var data = [];
    
        var req = protocols[protocol].request(params.options, function(res) {
    
            res.on('data', function(chunk) {
                data.push(chunk);
                //console.log(chunk.toString());
            });
    
            res.on('end', function(){
                //console.log(res.statusCode);
                //console.log(res.statusMessage);
                // console.log(res.headers);
                let responsebody;
                if(res.headers.hasOwnProperty('content-type') && res.headers['content-type'].indexOf('application/json') >= 0) {
                    try {
                        responsebody = JSON.parse(new Buffer.concat(data).toString());
                    } catch(e) {
                        console.log('Invalid response from platform: ');
                        console.log(new Buffer.concat(data).toString());
                        callback('connection failure', e);
                        return;
                    }
                } else {
                    responsebody = new Buffer.concat(data).toString();
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
                callback('connection failure', e.message);
            });
        });
    
        req.on('error', function(e){
            console.log('Failed to connect to platform: ');
            console.log(e.message);
            callback('connection failure', e.message);
        });
    
        if(params.body) {
            req.write(params.body);
        } else {
            //req.write();
        }
    
        req.end();
    }
}