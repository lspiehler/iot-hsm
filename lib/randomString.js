const cryptoRandomString = require('crypto-random-string');

module.exports = {
    generate: function(params, callback) {
        let randomstring = cryptoRandomString({length: params.length, characters: params.characters});
        callback(false, randomstring);
    }
}