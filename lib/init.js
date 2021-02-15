var openssl = require('../lib/openssl');
var config = require('../config');

openssl.readPKCS11Cert({slotid: '01'}, function(err, out) {
    if(err) {
        console.log(err);
    } else {
      openssl.getCertInfo(out, function(err, attrs, cmd) {
        if(err) {
            console.log(err);
        } else {
            module.exports
        }
    