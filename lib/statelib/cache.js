const fs = require('fs');
const config = require('../../config');
var state;

module.exports = {
    read: function() {
        return state;
    },
    write: function(newState, persist) {
        // console.log('Writing state to memory and disk...');
        // console.log(newState);
        if(persist) {
            fs.writeFile(config.STATEDIR + '/state.json', JSON.stringify(newState, null, 2), function(err) {
                if(err) {
                    console.log('Error writing state to disk:', err);
                }
            });
        }
        state = newState;
    }
}