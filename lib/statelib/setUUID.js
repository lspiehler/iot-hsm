const cache = require('./cache');

module.exports = function(params, callback) {
    //need to get uri
    // console.log(params);
    var state = require('./get')();
    if(!state.hasOwnProperty('uuid')) {
        state.uuid = params.uuid;
    }
    cache.write(state, true);
    callback(false, state);
}