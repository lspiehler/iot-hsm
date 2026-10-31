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
module.exports.__t = { messageReceived: messageReceived, setCerts: function(c) { certs = c; }, getQueue: getQueue, setBadpin: function(b) { badpin = b; } };`, iotfile);
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
        // as pkcs11-tool --list-slots reported them for a YubiKey 5 on the user's appliance
        'token flags': ['login required', 'rng', 'token initialized', 'PIN initialized'],
        'token flags read': '2026-10-31T16:00:00.000Z',
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
        // as lib/agentInfo.js reads it: never from a repository above the agent's directory
        let env = Object.assign({}, process.env, { GIT_CEILING_DIRECTORIES: path.dirname(root) });
        let head = (await run('git', ['rev-parse', 'HEAD'], { cwd: root, env: env })).stdout.trim();
        assert.equal(agent.commit, head);
    }
});

test('capabilities: native signing, the request kinds and the algorithm of the CA key', function() {
    let capabilities = agentinfo.offerFields(caEntry()).capabilities;
    assert.equal(capabilities.nativeSigning, false);
    assert.deepEqual(capabilities.signTypes, ['csr', 'cms', 'crl']);
    assert.deepEqual(capabilities.algorithm, { key: 'rsa', bits: 2048, certificateHash: 'sha256' });
    // a Google KMS key allows one hash
    let kms = agentinfo.offerFields(caEntry({ base64: ecca, module: KMS, 'token flags': ['token initialized'], private_key: { 'Allowed mechanisms': 'ECDSA-SHA384' } }));
    assert.deepEqual(kms.capabilities.algorithm, { key: 'ec', curve: 'secp384r1', certificateHash: 'sha384' });
    // an unreadable CA certificate leaves the algorithm out
    assert.equal(agentinfo.offerFields(caEntry({ base64: 'not a certificate' })).capabilities.algorithm, undefined);
});

test('token: its type and the PIN state from the token flags', function() {
    let token = function(params) { return agentinfo.offerFields(caEntry(params)).token; };
    const read = '2026-10-31T16:00:00.000Z';
    assert.deepEqual(token(), { type: 'yubikey', pinState: 'ok', pinStateRead: read });
    assert.deepEqual(token({ module: KMS, 'token flags': ['token initialized'] }), { type: 'google' });
    assert.deepEqual(token({ module: '/usr/lib/softhsm/libsofthsm2.so' }), { type: 'softhsm', pinState: 'ok', pinStateRead: read });
    assert.deepEqual(token({ module: '/opt/vendor/libother.so' }), { type: 'unknown', pinState: 'ok', pinStateRead: read });
    // a PIN the agent's login failed with is the state now, not as of the slot listing
    assert.deepEqual(agentinfo.offerFields(caEntry(), { badpin: true }).token, { type: 'yubikey', pinState: 'rejected' });
    // also when the slot listing had no token flags
    assert.deepEqual(agentinfo.offerFields(caEntry({ 'token flags': undefined }), { badpin: true }).token, { type: 'yubikey', pinState: 'rejected' });
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

// sends a solicitation for the CA through the offer handler and returns the signed part of the agent's reply
const solicit = async function(ca, siguuid, type) {
    iot.setCerts([ca]);
    sent.length = 0;
    let request = { serial: '0102', thumbprint: 'aabb', siguuid: siguuid };
    let err = await new Promise(function(resolve) {
        iot.messageReceived({ publisher: 'platform', channel: 'channel-id-1', message: { type: 'solicit signature', ttl: 10, smime: JSON.stringify(request) } }, resolve);
    });
    assert.equal(err, false);
    assert.equal(sent.length, 1);
    assert.equal(sent[0].unsigned.type, type || 'services offerred');
    return JSON.parse(sent[0].signed);
}

test('the signed offer carries the fields next to the ones the platform reads', async function() {
    let before = Date.now();
    let signed = await solicit(caEntry(), 'sig-1');
    assert.equal(signed.uuid, 'agent-uuid');
    assert.equal(signed.caindex, 0);
    assert.equal(signed.siguuid, 'sig-1');
    assert.equal(signed.subjectEscaping, true);
    assert.equal(signed.busy, undefined);
    assert.equal(signed.agent.version, pkg.version);
    assert.equal(signed.token.type, 'yubikey');
    assert.deepEqual(signed.capabilities.signTypes, ['csr', 'cms', 'crl']);
    // the clock is read when the reply is sent
    assert.ok(Date.parse(signed.agent.clock) >= before);
});

test('a part that fails is left out on its own; the version stays', async function() {
    let ca = caEntry();
    // a CA entry a future change could break the details with
    Object.defineProperty(ca, 'token flags', { get: function() { throw new Error('broken'); } });
    let signed = await solicit(ca, 'sig-2');
    assert.equal(signed.caindex, 0);
    assert.equal(signed.subjectEscaping, true);
    assert.equal(signed.agent.version, pkg.version);
    assert.ok(signed.capabilities);
    assert.equal(signed.token, undefined);
});

test('if building the details fails altogether, the offer still goes out without them', async function() {
    let real = agentinfo.offerFields;
    agentinfo.offerFields = function() { throw new Error('broken'); };
    try {
        let signed = await solicit(caEntry(), 'sig-3');
        assert.equal(signed.caindex, 0);
        assert.equal(signed.subjectEscaping, true);
        assert.equal(signed.agent, undefined);
    } finally {
        agentinfo.offerFields = real;
    }
});

test('a busy reply carries the details too, and the PIN state the agent saw', async function() {
    let ca = caEntry();
    // one signature takes 4 s and three wait, so another can't finish within the 10 s TTL
    let queue = iot.getQueue(ca);
    queue.running = queue.limit;
    for(let i = 0; i < 3; i++) {
        queue.tasks.push({ expires: Infinity, task: function() {} });
    }
    queue.duration = 4000;
    iot.setBadpin({ '10101010': true });
    try {
        let signed = await solicit(ca, 'sig-4', 'services busy');
        assert.equal(signed.busy, true);
        assert.equal(signed.agent.version, pkg.version);
        assert.equal(signed.token.pinState, 'rejected');
    } finally {
        iot.setBadpin({});
        queue.running = 0;
        queue.tasks.length = 0;
        queue.duration = 0;
    }
});
