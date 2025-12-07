const cache = require('./cache');
var openssl2 = require('../openssl2');

module.exports = function(params, callback) {
    //need to get uri
    // console.log(params);
    var state = require('./get')();
    if(!state.hasOwnProperty('certificates')) {
        state.certificates = {};
    }
    if(!state.certificates.hasOwnProperty(params.serial)) {
        state.certificates[params.serial] = {};
    }
    if(!state.certificates[params.serial].hasOwnProperty(params.objectid)) {
        state.certificates[params.serial][params.objectid] = {};
    }

    state.certificates[params.serial][params.objectid]['Certificate Object'] = [{}];
    state.certificates[params.serial][params.objectid]['Certificate Object'][0]['base64'] = params.cert;

    openssl2.x509.parse({cert: params.cert}, function(err, attrs) {
        if(err) {
            callback(err, false);
        } else {
            //console.log(attrs.data);
            state.certificates[params.serial][params.objectid]['Certificate Object'][0]['type'] = 'Certificate Object';
            state.certificates[params.serial][params.objectid]['Certificate Object'][0]['detail'] = 'X.509 cert';
            state.certificates[params.serial][params.objectid]['Certificate Object'][0]['label'] = params.objectid;
            state.certificates[params.serial][params.objectid]['Certificate Object'][0]['subject'] = attrs.data.attributes['Subject String'];
            state.certificates[params.serial][params.objectid]['Certificate Object'][0]['serial'] = attrs.data.attributes['Serial Number'].split(":").join("").toUpperCase();
            state.certificates[params.serial][params.objectid]['Certificate Object'][0]['ID'] = params.objectid;
            // state.certificates[params.serial][params.objectid]['Certificate Object'][0]['uri'] = 'path'; // need to populate uri properly
            if(typeof(attrs.data.subject.commonName)=='string') {
                attrs.data.subject.commonName = [attrs.data.subject.commonName];
            }
            attrs.data.distinguishedName = openssl2.x509.getDistinguishedName(attrs.data.subject)
            let certattrs = attrs.data;
            state.certificates[params.serial][params.objectid]['Certificate Object'][0]['certinfo'] = certattrs;
            cache.write(state, true);
            callback(false, state);
        }
    });
}