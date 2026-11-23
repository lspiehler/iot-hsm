// lib/pinCheck.js: a login to the token with pkcs11-tool tells a rejected PIN from a key pkcs11-provider couldn't read for
// another reason. A fake pkcs11-tool on PATH answers as the real one does (SoftHSM, OpenSC 0.25), so no token is used. Run: npm test
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.join(__dirname, '..');
const pincheck = require(path.join(root, 'lib/pinCheck'));
const pkcs11tool = require(path.join(root, 'lib/pkcs11ToolCommand'));

// the fake pkcs11-tool writes its arguments and the PIN it was given to a log, then answers as FAKE_PKCS11 says
const bin = fs.mkdtempSync(path.join(os.tmpdir(), 'pincheck-bin-'));
const log = path.join(bin, 'calls.log');
fs.writeFileSync(path.join(bin, 'pkcs11-tool'), `#!/bin/bash
pin=""
for a in "$@"; do if [ "$prev" = "--pin" ]; then pin="$a"; fi; prev="$a"; done
case "$pin" in env:*) var="\${pin#env:}"; pin="\${!var}";; esac
echo "args: $* | pin: $pin" >> "${log}"
case "$FAKE_PKCS11" in
  ok) echo "Private Key Object; RSA"; exit 0;;
  wrong) echo "error: PKCS11 function C_Login failed: rv = CKR_PIN_INCORRECT (0xa0)" >&2; echo "Aborting." >&2; exit 1;;
  locked) echo "error: PKCS11 function C_Login failed: rv = CKR_PIN_LOCKED (0xa4)" >&2; exit 1;;
  device) echo "error: PKCS11 function C_Login failed: rv = CKR_DEVICE_ERROR (0x30)" >&2; echo "Aborting." >&2; exit 1;;
  stubborn) trap '' TERM; echo $$ > "${bin}/stubborn.pid"; exec sleep 30;;
  slot) echo "error: PKCS11 function C_OpenSession failed: rv = CKR_SLOT_ID_INVALID (0x3)" >&2; echo "Aborting." >&2; exit 1;;
  slow) sleep 0.2; echo "Private Key Object; RSA"; exit 0;;
  hang) exec sleep 30;;
esac
exit 3
`, { mode: 0o755 });
const PATH = process.env.PATH;
const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'pincheck-empty-'));

test.beforeEach(function() {
    process.env.PATH = bin + path.delimiter + PATH;
    fs.rmSync(log, { force: true });
});
test.after(function() {
    process.env.PATH = PATH;
    fs.rmSync(bin, { recursive: true, force: true });
    fs.rmSync(empty, { recursive: true, force: true });
});

const params = { module: '/usr/lib/softhsm/libsofthsm2.so', slotid: '0x2a', serial: '761572835c8025df', pin: '12 34\\56' };
const check = function(p) {
    return new Promise(function(resolve) { pincheck.checkPin(p || params, function(result, detail) { resolve({ result, detail }); }); });
}
const calls = function() {
    return fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n') : [];
}

test('the token\'s answer to a login: accepted, rejected (incorrect or locked) or unknown', async function() {
    for(let [mode, result, detail] of [
        ['ok', 'accepted', ''],
        ['wrong', 'rejected', 'CKR_PIN_INCORRECT'],
        ['locked', 'rejected', 'CKR_PIN_LOCKED'],
        // a login that fails for another reason says nothing about the PIN
        ['device', 'unknown', 'error: PKCS11 function C_Login failed: rv = CKR_DEVICE_ERROR (0x30)'],
        ['slot', 'unknown', 'error: PKCS11 function C_OpenSession failed: rv = CKR_SLOT_ID_INVALID (0x3)']
    ]) {
        process.env.FAKE_PKCS11 = mode;
        assert.deepEqual(await check(), { result, detail }, mode);
    }
});

test('the login is on the token\'s slot, with the PIN through the environment, never in the arguments', async function() {
    process.env.FAKE_PKCS11 = 'ok';
    await check();
    let [call] = calls();
    assert.match(call, /^args: --module \/usr\/lib\/softhsm\/libsofthsm2.so --slot 0x2a --login --pin env:IOTHSM_PIN_\d+ --list-objects --type privkey \| pin: 12 34\\56$/);
});

test('two failures on one token at once share one login, so a wrong PIN costs one try', async function() {
    process.env.FAKE_PKCS11 = 'slow';
    let results = await Promise.all([check(), check()]);
    assert.deepEqual(results.map(function(r) { return r.result; }), ['accepted', 'accepted']);
    assert.equal(calls().length, 1);
    // another token is checked on its own
    await Promise.all([check(), check(Object.assign({}, params, { serial: 'another' }))]);
    assert.equal(calls().length, 3);
});

test('no PIN, no pkcs11-tool, or no answer: unknown, and the agent keeps running', async function() {
    assert.deepEqual(await check(Object.assign({}, params, { pin: undefined })), { result: 'unknown', detail: 'the agent has no PIN for the token' });
    assert.equal(calls().length, 0);
    process.env.PATH = empty;
    let missing = await check();
    assert.equal(missing.result, 'unknown');
    assert.match(missing.detail, /ENOENT/);
    // pkcs11-tool stopped by its time limit
    process.env.PATH = bin + path.delimiter + PATH;
    let run = pkcs11tool.run;
    pkcs11tool.run = function(cmd, options, callback) { callback('', { exitcode: null, stderr: '' }); };
    try {
        assert.deepEqual(await check(), { result: 'unknown', detail: 'pkcs11-tool gave no answer in 5 s' });
    } finally {
        pkcs11tool.run = run;
    }
});

test('a pkcs11-tool that ignores its time limit doesn\'t hold up the checks after it', async function() {
    process.env.FAKE_PKCS11 = 'stubborn';
    let started = Date.now();
    assert.deepEqual(await check(), { result: 'unknown', detail: 'pkcs11-tool gave no answer in 5 s' });
    assert.ok(Date.now() - started < 9000);
    process.env.FAKE_PKCS11 = 'ok';
    assert.deepEqual(await check(), { result: 'accepted', detail: '' });
    // what the agent can't do yet (the later library change): stop it for good
    process.kill(parseInt(fs.readFileSync(path.join(bin, 'stubborn.pid'), 'utf8')), 'SIGKILL');
});

test('pkcs11-tool\'s result names the PIN only as its environment variable', async function() {
    process.env.FAKE_PKCS11 = 'ok';
    let out = await new Promise(function(resolve) { pkcs11tool.run(['--module', 'm', '--login', '--pin', 'secret-pin'], function(err, out) { resolve(out); }); });
    assert.match(out.command, /--pin env:IOTHSM_PIN_\d+/);
    assert.ok(out.command.indexOf('secret-pin') < 0);
    out = await new Promise(function(resolve) { pkcs11tool.run('--module m --login --pin secret-pin', function(err, out) { resolve(out); }); });
    assert.ok(out.command.indexOf('secret-pin') < 0);
});

test('pkcs11-tool runs no longer than its time limit, and a missing pkcs11-tool is an error, not a crash', async function() {
    process.env.FAKE_PKCS11 = 'hang';
    let started = Date.now();
    let out = await new Promise(function(resolve) { pkcs11tool.run(['--module', 'm', '--login'], { timeout: 200 }, function(err, out) { resolve(out); }); });
    assert.equal(out.exitcode, null);
    assert.ok(Date.now() - started < 5000);
    process.env.PATH = empty;
    let err = await new Promise(function(resolve) { pkcs11tool.run('--module m --show-info', function(err) { resolve(err); }); });
    assert.equal(err.code, 'ENOENT');
});
