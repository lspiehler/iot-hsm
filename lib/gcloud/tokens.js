const { parse, stringify } = require("yaml");
const fs = require('fs');

module.exports = {
    get: function(callback) {
        fs.readFile(__dirname + '/../../state/pkcs11-kms.yml', 'utf8', (err, data) => {
            if (err) {
                callback(false, []);
            } else {
                let tokens = parse(data);
                callback(false, tokens);
            }
        });
    }
}