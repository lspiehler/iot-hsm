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
    renewCert: function(cert, callback) { use('renewal')({}, callback); },
    getCert: function(cert, callback) { if(channel.current) { callback(false, 'channel cert'); } else { use('channel')({}, callback); } }
} });

// the PIN check logs in to the token; here it answers what the test says, and counts its calls
const pincheck = require(path.join(root, 'lib/pinCheck'));
const check = { result: 'accepted', calls: [] };
pincheck.checkPin = function(params, callback) {
    check.calls.push(params);
    setImmediate(function() { callback(check.result, check.result == 'unknown' ? 'pkcs11-tool gave no answer in 10 s' : ''); });
};

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
    setBadpin: function(b) { badpin = b; }, getQueue: getQueue, scheduleRenewal: scheduleRenewal, getChannels: getChannels, signMessage: signMessage };`, iotfile);
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
        'token hexid': '0x2a',
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
    check.result = 'accepted';
    check.calls.length = 0;
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

// pkcs11-provider (OpenSSL 3.0.13 + pkcs11-provider 0.3 on Ubuntu 24.04, SoftHSM) reports a rejected PIN for csr and crl only as a key
// it couldn't read; the same message comes from two key loads racing on one token with the right PIN (agent 1.0.1's parallel signing)
const PROVIDER_UNREADABLE_KEY = 'Using configuration from openssl.cnf\nCould not read CA private key from pkcs11:serial=' + SERIAL + ';id=%10;type=private\n';

// waits for done() (zlib and the stubs answer on later turns of the event loop; setTimeout may be mocked), up to 5 s
const settle = async function(done) {
    let started = Date.now();
    while(!done() && Date.now() - started < 5000) {
        await new Promise(setImmediate);
    }
}
// lets what is already under way finish, for checking that something did not happen
const flush = async function() {
    for(let i = 0; i < 100; i++) {
        await new Promise(setImmediate);
    }
}

test('a key pkcs11-provider couldn\'t read stops the token only when a login to the token rejects the PIN', async function() {
    for(let signtype of ['csr', 'crl']) {
        for(let [result, stopped] of [['rejected', true], ['accepted', false], ['unknown', false]]) {
            iot.setBadpin({});
            ca.channel.message = undefined;
            token.uses.length = 0;
            sent.length = 0;
            check.calls.length = 0;
            check.result = result;
            token.error = PROVIDER_UNREADABLE_KEY;
            await requestSignature(signtype, 'unreadable-' + signtype + '-' + result);
            // the token is asked with the agent's PIN, on its own slot
            assert.equal(check.calls.length, 1, signtype + ' ' + result);
            assert.deepEqual(check.calls[0], { module: ca.module, slotid: ca['token hexid'], serial: SERIAL, pin: '123456' });
            assert.equal(iot.getBadpin()[SERIAL] === true, stopped, signtype + ' ' + result);
            assert.equal(ca.channel.message, stopped ? 'Invalid PIN' : undefined);
            // the platform gets the signing error either way
            assert.equal(lastReply().signed.success, false);
            assert.equal(lastReply().signed.message, PROVIDER_UNREADABLE_KEY);
            // a rejected PIN isn't tried again; otherwise the next request uses the token (failing for another reason, so a
            // CRL isn't delivered to the platform)
            token.error = 'Could not sign: another reason';
            await requestSignature(signtype, 'unreadable-' + signtype + '-' + result + '-2');
            assert.deepEqual(token.uses, stopped ? [signtype] : [signtype, signtype], signtype + ' ' + result);
        }
    }
});

test('a login failure stops the token without asking it again, and other errors don\'t ask it at all', async function() {
    token.error = NATIVE_WRONG_PIN;
    await requestSignature('csr', 'login-1');
    assert.equal(iot.getBadpin()[SERIAL], true);
    assert.equal(check.calls.length, 0);
    iot.setBadpin({});
    token.error = 'Could not sign the request: unsupported extension';
    await requestSignature('csr', 'other-1');
    assert.equal(check.calls.length, 0);
    assert.equal(iot.getBadpin()[SERIAL], undefined);
});

test('a signature still running after the time limit has the PIN checked; the queue moves on after 5 s, no reply is made up, and a late result is handled as usual', async function(t) {
    t.mock.timers.enable({ apis: ['setTimeout'] });
    let slotlib = require(path.join(root, 'lib/slotlib'));
    let signCMS = slotlib.signCMS;
    let pending = [];
    slotlib.signCMS = function(params, callback) { pending.push(callback); };
    try {
        for(let [result, stopped] of [['accepted', false], ['rejected', true]]) {
            iot.setBadpin({});
            check.calls.length = 0;
            check.result = result;
            sent.length = 0;
            let request = { siguuid: 'hang-' + result, request: { options: { inform: 'PEM', outform: 'PEM' } } };
            await receive({ type: 'signature request', ttl: 10, caindex: 0, signtype: 'cms', smime: zlib.deflateSync(JSON.stringify(request)).toString('base64') });
            let queue = iot.getQueue(ca);
            await settle(function() { return pending.length > 0; });
            assert.equal(pending.length, 1);
            t.mock.timers.tick(5000);
            assert.equal(queue.running, 0);
            assert.equal(check.calls.length, 0);
            t.mock.timers.tick(10000);
            await settle(function() { return iot.getBadpin()[SERIAL] === stopped || (!stopped && check.calls.length > 0); });
            await flush();
            assert.equal(check.calls.length, 1, result);
            assert.equal(iot.getBadpin()[SERIAL] === true, stopped, result);
            assert.equal(sent.length, 0);
            // the signature ends after all: its result goes to the platform as before
            pending.shift()(false, 'signed late');
            await settle(function() { return sent.length > 0; });
            assert.equal(lastReply().signed.success, true);
            assert.equal(lastReply().signed.message, 'signed late');
        }
    } finally {
        slotlib.signCMS = signCMS;
    }
});

test('SIGNATURE_TIME_LIMIT sets the time limit in seconds', async function(t) {
    let config = require(path.join(root, 'config'));
    let limit = config.SIGNATURE_TIME_LIMIT;
    config.SIGNATURE_TIME_LIMIT = '30';
    t.mock.timers.enable({ apis: ['setTimeout'] });
    let slotlib = require(path.join(root, 'lib/slotlib'));
    let signCSR = slotlib.signCSR;
    let pending = [];
    slotlib.signCSR = function(params, callback) { pending.push(callback); };
    try {
        let request = { siguuid: 'limit-30', request: { csr: 'csr', options: {} } };
        await receive({ type: 'signature request', ttl: 10, caindex: 0, signtype: 'csr', smime: zlib.deflateSync(JSON.stringify(request)).toString('base64') });
        await settle(function() { return pending.length > 0; });
        t.mock.timers.tick(29000);
        await flush();
        assert.equal(check.calls.length, 0);
        t.mock.timers.tick(1000);
        await settle(function() { return check.calls.length > 0; });
        assert.equal(check.calls.length, 1);
        pending.shift()(false, 'signed');
        await settle(function() { return sent.length > 0; });
    } finally {
        slotlib.signCSR = signCSR;
        config.SIGNATURE_TIME_LIMIT = limit;
    }
});

test('a channel renewal whose key pkcs11-provider couldn\'t read stops the token when the login check rejects the PIN, and is tried again in 5 minutes otherwise', async function(t) {
    for(let [result, stopped] of [['rejected', true], ['accepted', false]]) {
        iot.setBadpin({});
        token.uses.length = 0;
        check.calls.length = 0;
        check.result = result;
        token.error = PROVIDER_UNREADABLE_KEY;
        ca.channel.certinfo.attributes['Not After'] = new Date(Date.now() + 5 * 60 * 1000).toISOString();
        t.mock.timers.enable({ apis: ['setTimeout'] });
        iot.scheduleRenewal(ca, 0);
        t.mock.timers.tick(0);
        await settle(function() { return check.calls.length > 0; });
        await flush();
        assert.deepEqual(token.uses, ['renewal']);
        assert.equal(check.calls[0].pin, '123456');
        assert.equal(iot.getBadpin()[SERIAL] === true, stopped, result);
        t.mock.timers.tick(5 * 60 * 1000);
        await settle(function() { return token.uses.length > 1; });
        assert.deepEqual(token.uses, stopped ? ['renewal'] : ['renewal', 'renewal'], result);
        t.mock.timers.reset();
    }
});

test('at slot load, a channel whose key pkcs11-provider couldn\'t read shows Invalid PIN when the login check rejects the PIN, and the error otherwise', async function() {
    channel.current = false;
    for(let [result, stopped] of [['rejected', true], ['accepted', false]]) {
        iot.setBadpin({});
        token.uses.length = 0;
        check.result = result;
        token.error = PROVIDER_UNREADABLE_KEY;
        await new Promise(function(resolve) { iot.getChannels([], [ca], 0, resolve); });
        assert.deepEqual(token.uses, ['channel']);
        assert.equal(ca.channel.id, false);
        assert.equal(ca.channel.message, stopped ? 'Invalid PIN' : PROVIDER_UNREADABLE_KEY, result);
        assert.equal(iot.getBadpin()[SERIAL] === true, stopped, result);
    }
    // a login failure stops it without asking the token
    iot.setBadpin({});
    check.calls.length = 0;
    token.error = NATIVE_WRONG_PIN;
    await new Promise(function(resolve) { iot.getChannels([], [ca], 0, resolve); });
    assert.equal(ca.channel.message, 'Invalid PIN');
    assert.equal(check.calls.length, 0);
});

test('characterization (before the PIN check): a channel certificate renewed for a message, whose key pkcs11-provider couldn\'t read, leaves the token in use', async function() {
    channel.current = false;
    token.error = PROVIDER_UNREADABLE_KEY;
    let err = await new Promise(function(resolve) { iot.signMessage({ cert: ca, signed: 'reply' }, resolve); });
    assert.equal(err, PROVIDER_UNREADABLE_KEY);
    assert.deepEqual(token.uses, ['channel']);
    assert.equal(iot.getBadpin()[SERIAL], undefined);
});
