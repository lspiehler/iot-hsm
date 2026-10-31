// A PIN the token rejected is not tried again until the slots are reloaded (lib/IoTHSM.js badpin).
// Runs the real lib/IoTHSM.js offer, signature and renewal paths; PubNub, the token (slotlib, statelib, pin) and
// the S/MIME encryption and signing are replaced, so nothing touches a token, PubNub or the platform. Run: npm test
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');
const Module = require('node:module');

const root = path.join(__dirname, '..');
process.env.STATEDIR = fs.mkdtempSync(path.join(os.tmpdir(), 'badpin-state-'));

const stub = function(file, exports) {
    let filename = require.resolve(path.join(root, file));
    require.cache[filename] = { id: filename, filename: filename, loaded: true, exports: exports };
}
// every use of the token; the error is what the next one returns
const token = { uses: [], error: false };
const use = function(kind) {
    return function(params, callback) {
        token.uses.push(kind);
        callback(token.error, token.error ? false : 'signed ' + kind);
    }
}
stub('lib/slotlib', { signCSR: use('csr'), signCMS: use('cms'), signCRL: use('crl') });
stub('lib/statelib', { get: function() { return {}; } });
stub('lib/pubnub', function() {});
stub('lib/pin', { getPins: function(params, callback) { callback(false, { USERPIN: '123456' }); } });
// a channel certificate that isn't current is renewed on the token
const channel = { current: true };
stub('lib/smime/index', { x509: {
    lifetime: 60,
    isCurrent: function() { return channel.current; },
    renewCert: function(cert, callback) { use('renewal')({}, callback); }
} });

// load IoTHSM.js with its handlers exposed; the platform's signature check and the encryption and signing of replies are replaced
const sent = [];
const iotfile = path.join(root, 'lib/IoTHSM.js');
const iotmod = new Module(iotfile, module);
iotmod.filename = iotfile;
iotmod.paths = Module._nodeModulePaths(path.dirname(iotfile));
iotmod._compile(fs.readFileSync(iotfile, 'utf8') + `
verifyMessage = function(smime, callback) { callback(false, {data: Buffer.from(smime), signercert: 'platform cert'}); };
decryptChannel = function(channel, data, callback) { callback(false, {data: Buffer.from(data.toString(), 'base64')}); };
encryptMessage = function(params, callback) { callback(false, params.signed); };
sendSignedMessage = function(params, callback) { module.exports.__sent.push(params); callback(false, {}); };
pubnub = { getUUID: function() { return 'agent-uuid'; } };
module.exports.__t = { messageReceived: messageReceived, setCerts: function(c) { certs = c; }, getBadpin: function() { return badpin; },
    setBadpin: function(b) { badpin = b; }, getQueue: getQueue, scheduleRenewal: scheduleRenewal };`, iotfile);
iotmod.exports.__sent = sent;
const iot = iotmod.exports.__t;

const SERIAL = '10101010';
// an entry of IoTHSM.js's certs, as connectSlots builds it
const caEntry = function() {
    return {
        label: 'PKIaaS test CA',
        ID: '10',
        base64: 'not a certificate',
        certinfo: { attributes: { 'Serial Number': '01:02', 'Thumbprint': 'aa:bb', 'Not After': new Date(Date.now() + 3600 * 1000).toISOString() } },
        'token serial': SERIAL,
        'token flags': ['login required', 'token initialized'],
        module: '/usr/lib/x86_64-linux-gnu/libykcs11.so',
        channel: { id: 'channel-id-1', key: { base64: 'not a key', pass: '123456' }, certinfo: { attributes: { 'Not After': new Date(Date.now() + 3600 * 1000).toISOString() } } }
    };
}

// what native signing (node-pki-signer through lib/nativeSigning.js) and OpenSSL's PKCS#11 engine return for a wrong PIN
const NATIVE_WRONG_PIN = 'PKCS#11 login: CKR_PIN_INCORRECT';
const OPENSSL_WRONG_PIN = 'PKCS11_login:... Login failed';

var ca;
test.beforeEach(function() {
    ca = caEntry();
    iot.setCerts([ca]);
    iot.setBadpin({});
    token.uses.length = 0;
    token.error = false;
    channel.current = true;
    sent.length = 0;
});

test.after(function() {
    fs.rmSync(process.env.STATEDIR, { recursive: true, force: true });
});

const receive = function(message) {
    return new Promise(function(resolve) {
        iot.messageReceived(Object.assign({ publisher: 'platform', channel: 'channel-id-1' }, { message: message }), resolve);
    });
}

const solicit = async function(siguuid) {
    let err = await receive({ type: 'solicit signature', ttl: 10, smime: JSON.stringify({ serial: '0102', thumbprint: 'aabb', siguuid: siguuid }) });
    assert.equal(err, false);
}

// a signature request goes through the token's queue; resolves when the queue is empty again
const requestSignature = async function(signtype, siguuid) {
    let request = { siguuid: siguuid, request: { csr: 'csr', options: { inform: 'PEM', outform: 'PEM' }, database: [], days: 1 } };
    let err = await receive({ type: 'signature request', ttl: 10, caindex: 0, signtype: signtype, smime: zlib.deflateSync(JSON.stringify(request)).toString('base64') });
    assert.equal(err, false);
    await waitForQueue();
}

const waitForQueue = async function() {
    let queue = iot.getQueue(ca);
    while(queue.running > 0 || queue.tasks.length > 0) {
        await new Promise(function(resolve) { setTimeout(resolve, 5); });
    }
}

// the signed part of the last reply, with its type
const lastReply = function() {
    assert.ok(sent.length > 0, 'a reply was sent');
    let last = sent[sent.length - 1];
    return { type: last.unsigned.type, signed: JSON.parse(last.signed) };
}

test('a signature whose login fails stops the token: no further offers or signatures with the same PIN', async function() {
    for(let [signtype, error] of [['csr', NATIVE_WRONG_PIN], ['cms', OPENSSL_WRONG_PIN], ['crl', OPENSSL_WRONG_PIN]]) {
        iot.setBadpin({});
        token.uses.length = 0;
        sent.length = 0;
        token.error = error;
        await requestSignature(signtype, 'sig-' + signtype);
        assert.deepEqual(token.uses, [signtype]);
        assert.equal(iot.getBadpin()[SERIAL], true, signtype);
        assert.equal(ca.channel.message, 'Invalid PIN');
        // the platform gets the failure
        let reply = lastReply();
        assert.equal(reply.type, 'signature response');
        assert.equal(reply.signed.success, false);
        // the next request isn't signed: the token isn't used again
        sent.length = 0;
        await requestSignature(signtype, 'sig-' + signtype + '-2');
        assert.deepEqual(token.uses, [signtype], signtype);
        reply = lastReply();
        assert.equal(reply.signed.success, false);
        assert.equal(reply.signed.siguuid, 'sig-' + signtype + '-2');
        assert.match(reply.signed.message, /PIN for this token was rejected/);
        // and it doesn't name the token
        assert.ok(reply.signed.message.indexOf(SERIAL) < 0);
    }
});

test('signatures queued behind the one whose login failed are not tried with the same PIN', async function() {
    token.error = NATIVE_WRONG_PIN;
    let requests = [];
    for(let i = 0; i < 3; i++) {
        let request = { siguuid: 'queued-' + i, request: { csr: 'csr', options: {} } };
        requests.push(receive({ type: 'signature request', ttl: 10, caindex: 0, signtype: 'csr', smime: zlib.deflateSync(JSON.stringify(request)).toString('base64') }));
    }
    await Promise.all(requests);
    await waitForQueue();
    // a YubiKey allows three tries
    assert.deepEqual(token.uses, ['csr']);
    assert.equal(sent.length, 3);
});

test('other signing errors leave the PIN alone', async function() {
    token.error = 'Could not sign the request: unsupported extension';
    await requestSignature('csr', 'sig-other');
    assert.equal(iot.getBadpin()[SERIAL], undefined);
    token.error = false;
    await requestSignature('csr', 'sig-other-2');
    assert.deepEqual(token.uses, ['csr', 'csr']);
    assert.equal(lastReply().signed.success, true);
});

test('while the PIN is rejected, a solicitation gets a signed busy reply that says why, not an offer', async function() {
    iot.setBadpin({ [SERIAL]: true });
    await solicit('sol-1');
    let reply = lastReply();
    assert.equal(reply.type, 'services busy');
    assert.equal(reply.signed.busy, true);
    assert.equal(reply.signed.siguuid, 'sol-1');
    assert.equal(reply.signed.token.pinState, 'rejected');
    assert.deepEqual(token.uses, []);
});

test('while the PIN is rejected, an expired channel certificate is not renewed for a reply', async function() {
    iot.setBadpin({ [SERIAL]: true });
    channel.current = false;
    await solicit('sol-2');
    await requestSignature('csr', 'sig-expired');
    await waitForQueue();
    assert.equal(sent.length, 0);
    assert.deepEqual(token.uses, []);
});

test('an offer waiting for a channel certificate renewal is dropped when the PIN is rejected meanwhile', async function() {
    channel.current = false;
    // a signature on the token holds the queue, so the offer waits behind it
    let queue = iot.getQueue(ca);
    queue.running = queue.limit;
    await solicit('sol-3');
    assert.equal(queue.tasks.length, 1);
    iot.setBadpin({ [SERIAL]: true });
    queue.running = 0;
    // the queue moves on when a task finishes
    let task = queue.tasks.shift();
    await new Promise(function(resolve) { task.task(resolve); });
    assert.equal(sent.length, 0);
    assert.deepEqual(token.uses, []);
});

test('a renewal whose login fails stops the token, natively signed too, and later renewals are skipped', async function() {
    token.error = NATIVE_WRONG_PIN;
    // close to expiring, so the renewal doesn't wait for a quiet moment after the other tests' messages
    ca.channel.certinfo.attributes['Not After'] = new Date(Date.now() + 5 * 60 * 1000).toISOString();
    iot.scheduleRenewal(ca, 0);
    await new Promise(function(resolve) { setTimeout(resolve, 20); });
    await waitForQueue();
    assert.deepEqual(token.uses, ['renewal']);
    assert.equal(iot.getBadpin()[SERIAL], true);
    iot.scheduleRenewal(ca, 0);
    await new Promise(function(resolve) { setTimeout(resolve, 20); });
    await waitForQueue();
    assert.deepEqual(token.uses, ['renewal']);
});

test('with the PIN accepted, the token offers and signs as before', async function() {
    await solicit('sol-4');
    assert.equal(lastReply().type, 'services offerred');
    await requestSignature('csr', 'sig-ok');
    assert.deepEqual(token.uses, ['csr']);
    assert.equal(lastReply().signed.success, true);
});
