const fs = require('fs');
const config = require('../../config');
const cache = require('./cache');
const { raw } = require('express');

module.exports = function() {
    if(!cache.read()) {
        console.log('Loading state from disk...');
        try {
            fs.statSync(config.STATEDIR);
        } catch(err) {
            fs.mkdirSync(config.STATEDIR, { recursive: true });
        }

        try {
            fs.statSync(config.STATEDIR + '/state.json');
            let rawstate = fs.readFileSync(config.STATEDIR + '/state.json', 'utf8');
            // console.log(rawstate);
            cache.write(JSON.parse(rawstate), false);
        } catch(err) {
            cache.write({}, true);
        }
    } else {
        console.log('Retrieving state from memory...');
    }

    return cache.read();
}