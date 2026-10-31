// The optional details the agent adds to its signed "services offerred" replies (lib/agentInfo.js).
// Runs the real lib/IoTHSM.js offer path; PubNub, the token (slotlib, statelib) and the S/MIME signing are
// replaced, so nothing touches a token, PubNub or the platform. Run: npm test
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

const root = path.join(__dirname, '..');
process.env.STATEDIR = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-info-state-'));

const stub = function(file, exports) {
    let filename = require.resolve(path.join(root, file));
    require.cache[filename] = { id: filename, filename: filename, loaded: true, exports: exports };
}
stub('lib/slotlib', {});
stub('lib/statelib', { get: function() { return {}; } });
stub('lib/pubnub', function() {});
stub('lib/smime/index', { x509: { isCurrent: function() { return true; } } });

const agentinfo = require('../lib/agentInfo');
const pkg = require('../package.json');
const run = promisify(execFile);

// load IoTHSM.js with the offer handler exposed; the platform's signature check and the signing of the reply are replaced
const sent = [];
const iotfile = path.join(root, 'lib/IoTHSM.js');
const iotmod = new Module(iotfile, module);
iotmod.filename = iotfile;
iotmod.paths = Module._nodeModulePaths(path.dirname(iotfile));
iotmod._compile(fs.readFileSync(iotfile, 'utf8') + `
verifyMessage = function(smime, callback) { callback(false, {data: Buffer.from(smime)}); };
sendSignedMessage = function(params, callback) { module.exports.__sent.push(params); callback(false, {}); };
pubnub = { getUUID: function() { return 'agent-uuid'; } };
module.exports.__t = { messageReceived: messageReceived, setCerts: function(c) { certs = c; } };`, iotfile);
iotmod.exports.__sent = sent;
const iot = iotmod.exports.__t;

const YUBIKEY = '/usr/lib/x86_64-linux-gnu/libykcs11.so';
const KMS = '/usr/lib/kms/libkmsp11.so';
const SECRETS = ['123456', 'Sup3rSecretPin', '/usr/lib', 'channel-id-1', '10101010', 'Test CA token', 'PKIaaS test CA'];
var rsaca, ecca;

const selfSigned = async function(newkey) {
    let keyfile = path.join(process.env.STATEDIR, 'ca.key');
    let { stdout } = await run('openssl', ['req', '-x509', '-newkey', ...newkey, '-nodes', '-keyout', keyfile, '-subj', '/CN=PKIaaS test CA', '-days', '1']);
    fs.rmSync(keyfile);
    return stdout;
}

// an entry of IoTHSM.js's certs, as connectSlots builds it
const caEntry = function(params) {
    return Object.assign({
        label: 'PKIaaS test CA',
        ID: '10',
        base64: rsaca,
        certinfo: { attributes: { 'Serial Number': '01:02', 'Thumbprint': 'aa:bb' } },
        'token serial': '10101010',
        'token label': 'Test CA token',
        'token flags': ['rng', 'login required', 'PIN initialized', 'token initialized'],
        module: YUBIKEY,
        pin: 'Sup3rSecretPin',
        channel: { id: 'channel-id-1', key: { base64: 'not a key', pass: '123456' } }
    }, params);
}

test.before(async function() {
    rsaca = await selfSigned(['rsa:2048']);
    ecca = await selfSigned(['ec', '-pkeyopt', 'ec_paramgen_curve:P-384']);
    await promisify(agentinfo.load)();
});

test.after(function() {
    fs.rmSync(process.env.STATEDIR, { recursive: true, force: true });
});

test('agent: its version, the installed library versions, the OpenSSL command, Node and the clock', async function() {
    let before = Date.now();
    let agent = agentinfo.offerFields(caEntry()).agent;
    assert.equal(agent.version, pkg.version);
    for(let [field, name] of [['pubnub', 'pubnub'], ['nodePkiSigner', 'node-pki-signer'], ['nodeOpensslCert2', 'node-openssl-cert2']]) {
        let installed = JSON.parse(fs.readFileSync(path.join(root, 'node_modules', name, 'package.json'), 'utf8')).version;
        assert.equal(agent.versions[field], installed, field);
    }
    let { stdout } = await run('openssl', ['version']);
    assert.equal(agent.versions.openssl, stdout.split(' ')[1]);
    assert.equal(agent.versions.node, process.versions.node);
    assert.equal(agent.versions.nodeOpenssl, process.versions.openssl);
    let clock = Date.parse(agent.clock);
    assert.ok(clock >= before && clock <= Date.now(), agent.clock);
    if(fs.existsSync(path.join(root, '.git'))) {
        let head = (await run('git', ['rev-parse', 'HEAD'], { cwd: root })).stdout.trim();
        assert.equal(agent.commit, head);
    }
});

test('capabilities: native signing, the request kinds and the algorithm of the CA key', function() {
    let capabilities = agentinfo.offerFields(caEntry()).capabilities;
    assert.equal(capabilities.nativeSigning, false);
    assert.deepEqual(capabilities.signTypes, ['csr', 'cms', 'crl']);
    assert.deepEqual(capabilities.algorithm, { hash: 'sha256', key: 'rsa', bits: 2048 });
    // a Google KMS key allows one hash
    let kms = agentinfo.offerFields(caEntry({ base64: ecca, module: KMS, 'token flags': ['token initialized'], private_key: { 'Allowed mechanisms': 'ECDSA-SHA384' } }));
    assert.deepEqual(kms.capabilities.algorithm, { hash: 'sha384', key: 'ec', curve: 'secp384r1' });
    // an unreadable CA certificate leaves the algorithm out
    assert.equal(agentinfo.offerFields(caEntry({ base64: 'not a certificate' })).capabilities.algorithm, undefined);
});

test('token: its type and the PIN state from the token flags', function() {
    let token = function(params) { return agentinfo.offerFields(caEntry(params)).token; };
    assert.deepEqual(token(), { type: 'yubikey', pinState: 'ok' });
    assert.deepEqual(token({ module: KMS, 'token flags': ['token initialized'] }), { type: 'google' });
    assert.deepEqual(token({ module: '/usr/lib/softhsm/libsofthsm2.so' }), { type: 'softhsm', pinState: 'ok' });
    assert.deepEqual(token({ module: '/opt/vendor/libother.so' }), { type: 'unknown', pinState: 'ok' });
    assert.deepEqual(token({ 'token flags': undefined }), { type: 'yubikey' });
    let flags = ['login required', 'token initialized'];
    assert.equal(token({ 'token flags': flags.concat('user PIN count low') }).pinState, 'countLow');
    assert.equal(token({ 'token flags': flags.concat('user PIN count low', 'user PIN final try') }).pinState, 'finalTry');
    assert.equal(token({ 'token flags': flags.concat('user PIN locked') }).pinState, 'locked');
});

test('nothing that identifies the device or helps to use it, and no field an older platform reads', function() {
    let fields = agentinfo.offerFields(caEntry());
    let json = JSON.stringify(fields);
    for(let secret of SECRETS) {
        assert.ok(json.indexOf(secret) < 0, secret);
    }
    assert.ok(json.indexOf(os.hostname()) < 0, 'hostname');
    // pkiaas lib/pubnub/requestSign.js reads these from an offer
    for(let key of ['uuid', 'caindex', 'siguuid', 'subjectEscaping', 'busy']) {
        assert.ok(!fields.hasOwnProperty(key), key);
    }
    // the offer is a PubNub message (32 KiB in all, with the S/MIME signature and the channel certificate)
    assert.ok(json.length < 1024, json.length + ' bytes');
});

test('the signed offer carries the fields next to the ones the platform reads', async function() {
    let ca = caEntry();
    iot.setCerts([ca]);
    sent.length = 0;
    let solicit = { serial: '0102', thumbprint: 'aabb', siguuid: 'sig-1' };
    let err = await new Promise(function(resolve) {
        iot.messageReceived({ publisher: 'platform', channel: 'channel-id-1', message: { type: 'solicit signature', ttl: 10, smime: JSON.stringify(solicit) } }, resolve);
    });
    assert.equal(err, false);
    assert.equal(sent.length, 1);
    assert.equal(sent[0].unsigned.type, 'services offerred');
    let signed = JSON.parse(sent[0].signed);
    assert.equal(signed.uuid, 'agent-uuid');
    assert.equal(signed.caindex, 0);
    assert.equal(signed.siguuid, 'sig-1');
    assert.equal(signed.subjectEscaping, true);
    assert.equal(signed.busy, undefined);
    assert.equal(signed.agent.version, pkg.version);
    assert.equal(signed.token.type, 'yubikey');
    assert.deepEqual(signed.capabilities.signTypes, ['csr', 'cms', 'crl']);
});
