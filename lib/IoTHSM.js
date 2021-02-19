

var examineSlots = function(slots) {
    console.log(slots);
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
                            console.log(slots[i].objects[slotids[j]][objects[k]][l]);
                        }
                    }
                }
            }
        }
    }
}

module.exports = {
    examineSlots: function(slots, callback) {
        examineSlots(slots, function(err) {
            if(err) {
                callback(err);
            } else {
                callback(false);
            }
        });
    }
}