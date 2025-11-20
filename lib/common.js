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
    }
}