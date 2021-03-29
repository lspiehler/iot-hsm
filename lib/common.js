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
        if(slot.modulePath.indexOf('libykcs') >= 0) {
            return 'yubikey'
        } else {
            return 'softhsm';
        }
    }
}