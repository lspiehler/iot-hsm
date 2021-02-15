var certinfo = false;

function addCertInfo(certinf) {
    //console.log('here');
    if(certinfo===false) {
        certinfo = certinf; 
        //console.log(certinfo);
    } else {
        return 'Cannot change certinfo after it\'s been set';
    }
}

module.exports = {
    addCertinfo: function(certinfo) {
        addCertInfo(certinfo);
    },
    OPENSSLBINPATH: process.env.OPENSSLBINPATH || 'openssl',
    getCertInfo: function() {
        return certinfo;
    }
}