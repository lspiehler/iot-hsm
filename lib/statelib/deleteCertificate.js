const cache = require('./cache');

module.exports = function(params, slots, callback) {
    //need to get uri
    // console.log(params);
    // console.log(slots);
    let serial;
    for(let i = 0; i < slots.slots.length; i++) {
        if(slots.slots[i]['hexid'] == params.slotid && slots.slots[i]['modulePath'] == params.module) {
            serial = slots.slots[i]['serial num'];
            break;
        }
    }
    var state = require('./get')();
    if(!state.hasOwnProperty('certificates')) {
        state.certificates = {};
    }

    if(serial) {
        if(state.certificates.hasOwnProperty(serial)) {
            if(state.certificates[serial].hasOwnProperty(params.objectid)) {
                delete state.certificates[serial][params.objectid];
                cache.write(state, true);
                callback(false, state);
            } else {
                callback('Failed to find slot', false);
            }
        } else {
            callback('Failed to find slot', false);
        }
    } else {
        callback('Failed to find slot', false);
    }
}