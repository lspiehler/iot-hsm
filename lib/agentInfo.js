// Details about this agent that it adds to its signed "services offerred" replies, so the platform can show
// which version runs, what it can do and whether the token is healthy. Every field is optional: the platform
// must not require any of them, and platforms from before these fields ignore them.
// Nothing here may identify the device or help to use it: no PINs, keys, paths, channel IDs, hostname or
// token serial numbers.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');
const config = require('../config');
const common = require('./common');
const nativeSigning = require('./nativeSigning');
const pkg = require('../package.json');

const root = path.join(__dirname, '..');
// the npm packages whose versions are reported, by their field name
const packages = {
    pubnub: 'pubnub',
    nodePkiSigner: 'node-pki-signer',
    nodeOpensslCert2: 'node-openssl-cert2'
};
// the kinds of signature requests lib/IoTHSM.js handles (signtype)
const signTypes = ['csr', 'cms', 'crl'];

var info = {
    version: pkg.version,
    versions: {
        node: process.versions.node,
        nodeOpenssl: process.versions.openssl
    }
};
var loading = false;
// CA certificate → its key algorithm, read once
var algorithms = {};

var readPackageVersion = function(name, callback) {
    fs.readFile(path.join(root, 'node_modules', name, 'package.json'), 'utf8', function(err, data) {
        if(err) {
            callback(false);
        } else {
            try {
                callback(JSON.parse(data).version || false);
            } catch(e) {
                callback(false);
            }
        }
    });
}

// the commit of a git checkout; an install without .git (the Docker image) has none
var readCommit = function(callback) {
    execFile('git', ['rev-parse', 'HEAD'], {cwd: root, timeout: 10000}, function(err, stdout) {
        let commit = err ? '' : stdout.trim();
        callback(/^[0-9a-f]{40,64}$/.test(commit) ? commit : false);
    });
}

// the OpenSSL command the agent runs, which isn't the OpenSSL built into Node
var readOpenSSLVersion = function(callback) {
    execFile(config.opensslbinpath || 'openssl', ['version'], {timeout: 10000}, function(err, stdout) {
        let match = err ? null : /^OpenSSL (\S+)/.exec(stdout.trim());
        callback(match ? match[1] : false);
    });
}

// reads the versions once; offers sent before it finishes carry what is known so far
var load = function(callback) {
    callback = callback || function() {};
    if(loading) {
        callback(false);
        return;
    }
    loading = true;
    let names = Object.keys(packages);
    let pending = names.length + 2;
    let done = function() {
        pending--;
        if(pending == 0) {
            callback(false);
        }
    }
    names.forEach(function(name) {
        readPackageVersion(packages[name], function(version) {
            if(version) {
                info.versions[name] = version;
            } else {
                console.log('Unable to read the installed version of ' + packages[name] + ' for the services offer');
            }
            done();
        });
    });
    readCommit(function(commit) {
        if(commit) {
            info.commit = commit;
        }
        done();
    });
    readOpenSSLVersion(function(version) {
        if(version) {
            info.versions.openssl = version;
        } else {
            console.log('Unable to read the OpenSSL version for the services offer');
        }
        done();
    });
}

// e.g. {key: 'rsa', bits: 2048} or {key: 'ec', curve: 'prime256v1'}
var getKeyAlgorithm = function(ca) {
    if(!ca.base64) {
        return false;
    }
    if(!algorithms.hasOwnProperty(ca.base64)) {
        try {
            let key = new crypto.X509Certificate(ca.base64).publicKey;
            let algorithm = {key: key.asymmetricKeyType};
            let details = key.asymmetricKeyDetails || {};
            if(details.modulusLength) {
                algorithm.bits = details.modulusLength;
            }
            if(details.namedCurve) {
                algorithm.curve = details.namedCurve;
            }
            algorithms[ca.base64] = algorithm;
        } catch(e) {
            algorithms[ca.base64] = false;
        }
    }
    return algorithms[ca.base64];
}

// the token's PIN state from its PKCS#11 token flags when the slots were read; tokens don't tell how many tries are left
var getPinState = function(ca) {
    let flags = ca['token flags'];
    if(!Array.isArray(flags) || flags.indexOf('login required') < 0) {
        return false;
    }
    if(flags.indexOf('user PIN locked') >= 0) {
        return 'locked';
    } else if(flags.indexOf('user PIN final try') >= 0) {
        return 'finalTry';
    } else if(flags.indexOf('user PIN count low') >= 0) {
        return 'countLow';
    } else {
        return 'ok';
    }
}

// the optional fields for an offer for this CA (an entry of IoTHSM.js's certs)
var offerFields = function(ca) {
    let agent = {
        version: info.version,
        versions: Object.assign({}, info.versions),
        clock: new Date().toISOString()
    };
    if(info.commit) {
        agent.commit = info.commit;
    }
    let capabilities = {
        nativeSigning: nativeSigning.enabled(),
        signTypes: signTypes.slice()
    };
    let algorithm = getKeyAlgorithm(ca);
    if(algorithm) {
        //the hash slotlib signs certificates and CRLs with for this key
        let hash = 'sha256';
        if(ca.private_key) {
            hash = common.getAllowedHashAlg(ca.private_key);
        }
        capabilities.algorithm = Object.assign({hash: hash}, algorithm);
    }
    let token = {
        type: common.getTokenType({modulePath: ca.module || ''})
    };
    let pinstate = getPinState(ca);
    if(pinstate) {
        token.pinState = pinstate;
    }
    return {
        agent: agent,
        capabilities: capabilities,
        token: token
    };
}

module.exports = {
    load: load,
    offerFields: offerFields
}
