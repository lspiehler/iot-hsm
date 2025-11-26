const https = require('https');

module.exports = {
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
                    callback('connection failure', e);
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