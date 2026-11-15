// The signature request path for sign type 'ct-final' (CT final certificates) in the real lib/IoTHSM.js, with the token,
// PubNub and S/MIME replaced as in test/badpin.test.js.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');
const Module = require('node:module');

const root = path.join(__dirname, '..');
process.env.STATEDIR = fs.mkdtempSync(path.join(os.tmpdir(), 'ctfinal-state-'));

const stub = function(file, exports) {
    let filename = require.resolve(path.join(root, file));
    require.cache[filename] = { id: filename, filename: filename, loaded: true, exports: exports };
}
const token = { uses: [], error: false, calls: [] };
const use = function(kind) {
    return function(params, callback) {
        token.uses.push(kind);
        token.calls.push(params);
        callback(token.error, token.error ? false : 'signed ' + kind);
    }
}
stub('lib/slotlib', { signCSR: use('csr'), signCMS: use('cms'), signCRL: use('crl'), signFinalCertificate: use('ct-final') });
stub('lib/statelib', { get: function() { return {}; } });
stub('lib/pubnub', function() {});
stub('lib/pin', { getPins: function(params, callback) { callback(false, { USERPIN: 'the-user-pin' }); } });
const channel = { current: true };
stub('lib/smime/index', { x509: { lifetime: 60, isCurrent: function() { return channel.current; }, renewCert: function(cert, callback) { use('renewal')({}, callback); } } });

const nativeSigning = require(path.join(root, 'lib/nativeSigning'));

const sent = [];
const iotfile = path.join(root, 'lib/IoTHSM.js');
const iotmod = new Module(iotfile, module);
iotmod.filename = iotfile;
iotmod.paths = Module._nodeModulePaths(path.dirname(iotfile));
iotmod._compile(fs.readFileSync(iotfile, 'utf8') + `
verifyMessage = function(smime, callback) { callback(false, {data: Buffer.from(smime), signercert: 'platform cert'}); };
decryptChannel = function(channel, data, callback) { callback(false, {data: Buffer.from(data.toString(), 'base64')}); };
encryptMessage = function(params, callback) { callback(false, params.signed); };
sendSignedMessage = function(params, callback) { module.exports.__sent.push(params); callback(module.exports.__senderr || false, {}); };
pubnub = { getUUID: function() { return 'agent-uuid'; } };
module.exports.__t = { messageReceived: messageReceived, setCerts: function(c) { certs = c; }, getBadpin: function() { return badpin; },
    setBadpin: function(b) { badpin = b; }, getQueue: getQueue };`, iotfile);
iotmod.exports.__sent = sent;
const iot = iotmod.exports.__t;

const SERIAL = '10101010';
const caEntry = function() {
    return {
        label: 'PKIaaS test CA', ID: '10', base64: 'STORED CA CERT',
        certinfo: { attributes: { 'Serial Number': '01:02', 'Thumbprint': 'aa:bb', 'Not After': new Date(Date.now() + 3600 * 1000).toISOString() } },
        'token serial': SERIAL, 'token flags': ['login required', 'token initialized'],
        module: '/usr/lib/x86_64-linux-gnu/libykcs11.so',
        channel: { id: 'channel-id-1', key: { base64: 'not a key', pass: '123456' }, certinfo: { attributes: { 'Not After': new Date(Date.now() + 3600 * 1000).toISOString() } } }
    };
}

var ca;
test.beforeEach(function() {
    ca = caEntry(); iot.setCerts([ca]); iot.setBadpin({});
    token.uses.length = 0; token.calls.length = 0; token.error = false; channel.current = true; sent.length = 0;
    iotmod.exports.__senderr = false;
});
test.after(function() { fs.rmSync(process.env.STATEDIR, { recursive: true, force: true }); });

// resolves with the number of times the callback was called and the last err, after the queue drained
const receive = function(message) {
    return new Promise(function(resolve) {
        let calls = 0, last;
        iot.messageReceived(Object.assign({ publisher: 'platform', channel: 'channel-id-1' }, { message: message }), function(err) { calls++; last = err; });
        setTimeout(function() { resolve({ calls, last }); }, 30);
    });
}
const request = async function(signtype, siguuid, req) {
    let r = { siguuid: siguuid, request: req };
    let smime = zlib.deflateSync(JSON.stringify(r)).toString('base64');
    let queue = iot.getQueue(ca);
    // the queued task's callback is processQueue's; count replies instead
    await receive({ type: 'signature request', ttl: 10, caindex: 0, signtype: signtype, smime: smime });
    while(queue.running > 0 || queue.tasks.length > 0) { await new Promise(function(r) { setTimeout(r, 5); }); }
}
const lastReply = function() {
    assert.ok(sent.length > 0, 'a reply was sent');
    let last = sent[sent.length - 1];
    return { type: last.unsigned.type, signed: JSON.parse(last.signed), unsigned: last.unsigned, params: last };
}
const good = { precertificate: '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n', sctList: Buffer.from([4, 1, 0]).toString('base64') };

test('ct-final: success reply carries the final certificate; the CA cert and PIN come from the agent, not the message', async function() {
    assert.equal(nativeSigning.canSignFinalCertificates(), true);
    await request('ct-final', 'f-1', Object.assign({ ca: 'ATTACKER CA', publiccert: 'ATTACKER', pin: 'x', module: '/evil.so', objectid: '99' }, good));
    assert.deepEqual(token.uses, ['ct-final']);
    let p = token.calls[0];
    assert.equal(p.publiccert, 'STORED CA CERT');
    assert.equal(p.pin, 'the-user-pin');
    assert.equal(p.module, ca.module);
    assert.equal(p.objectid, '10');
    assert.equal(p.serial, SERIAL);
    assert.equal(p.precertificate, good.precertificate);
    assert.ok(Buffer.isBuffer(p.sctList));
    assert.deepEqual([...p.sctList], [4, 1, 0]);
    let reply = lastReply();
    assert.equal(sent.length, 1);
    assert.equal(reply.type, 'signature response');
    assert.deepEqual(reply.signed, { success: true, siguuid: 'f-1', message: 'signed ct-final' });
    assert.equal(reply.unsigned.siguuid, 'f-1');
});

test('ct-final: a malformed request is refused without touching the token, one reply each', async function() {
    let n = 0;
    for(let req of [undefined, null, 'string', {}, { precertificate: 'x' }, { sctList: 'x' }, { precertificate: 1, sctList: 'x' }, { precertificate: 'x', sctList: ['x'] }]) {
        await request('ct-final', 'bad-' + (n++), req);
        assert.deepEqual(token.uses, []);
        assert.equal(sent.length, n, JSON.stringify(req));
        let reply = lastReply();
        assert.equal(reply.signed.success, false);
        assert.match(reply.signed.message, /no precertificate or SCT list/);
    }
});

test('ct-final: a rejected PIN stops the token, also as pkcs11-provider reports it (a key it can\'t find)', async function() {
    for(let error of ['PKCS#11 login: CKR_PIN_INCORRECT', 'PKCS11_login:... Login failed', 'openssl dgst: Could not find private key from the token\'s key', 'openssl dgst: Could not open file or uri for loading key from the token\'s key']) {
        iot.setBadpin({}); token.uses.length = 0; sent.length = 0; token.error = error;
        await request('ct-final', 'pin-' + error.length, good);
        assert.deepEqual(token.uses, ['ct-final']);
        let reply = lastReply();
        assert.equal(reply.signed.success, false);
        assert.equal(reply.signed.message, error);
        assert.equal(iot.getBadpin()[SERIAL], true, error);
        // the next request doesn't use the token
        await request('ct-final', 'pin2-' + error.length, good);
        assert.deepEqual(token.uses, ['ct-final'], error);
    }
    // another failure leaves the token in use
    iot.setBadpin({}); token.error = 'check precertificate: it has an SCT list already';
    await request('ct-final', 'other-1', good);
    assert.equal(iot.getBadpin()[SERIAL], undefined);
});

test('ct-final: a replayed siguuid is ignored (no token use, no reply)', async function() {
    await request('ct-final', 'replay-1', good);
    assert.deepEqual(token.uses, ['ct-final']);
    await request('ct-final', 'replay-1', good);
    assert.deepEqual(token.uses, ['ct-final']);
    assert.equal(sent.length, 1);
});

test('ct-final: when node-pki-signer can\'t build final certificates the request is refused, not signed', async function(t) {
    t.mock.method(nativeSigning, 'canSignFinalCertificates', () => false);
    await request('ct-final', 'nocap-1', good);
    assert.deepEqual(token.uses, []);
    let reply = lastReply();
    assert.equal(reply.signed.success, false);
    assert.match(reply.signed.message, /needs Node 24.11/);
});

test('ct-final: when the reply cannot be sent the task still finishes once', async function() {
    iotmod.exports.__senderr = 'pubnub down';
    await request('ct-final', 'send-1', good);
    assert.deepEqual(token.uses, ['ct-final']);
    assert.equal(sent.length, 1);
});

test('old sign types: unchanged replies', async function() {
    for(let signtype of ['csr', 'cms']) {
        sent.length = 0;
        await request(signtype, 'old-' + signtype, { csr: 'csr', options: { inform: 'PEM', outform: 'PEM' }, database: [], days: 1 });
        assert.deepEqual(token.uses.at(-1), signtype);
        assert.equal(lastReply().signed.success, true);
        assert.equal(sent.length, 1);
    }
});

test('a Google KMS key whose key version isn\'t found is refused clearly, without signing', async function() {
    const config = require(path.join(root, 'config'));
    const saved = config.KMS_PKCS11_CONFIG;
    config.KMS_PKCS11_CONFIG = path.join(process.env.STATEDIR, 'no-such-kms-config.yaml');
    try {
        let err = await new Promise(function(resolve) {
            nativeSigning.signFinalCertificate({ precertificate: good.precertificate, sctList: Buffer.from([4, 1, 0]), ca: 'x', pkcs11: {} },
                { module: '/usr/lib/kms/libkmsp11.so', objectid: '10', publiccert: 'kms ca' }, function(err, cert) {
                    assert.equal(cert, false);
                    resolve(err);
                });
        });
        assert.match(err, /Google KMS key: its key version wasn't found/);
    } finally {
        config.KMS_PKCS11_CONFIG = saved;
    }
});
