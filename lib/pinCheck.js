// Whether a token accepts the agent's PIN, found by logging in to it on a new session with pkcs11-tool (the PIN goes through
// the environment, not the process list). OpenSSL's pkcs11-provider reports a rejected PIN only as a key it couldn't read, and
// two key loads racing on one token give the same message with the right PIN (agent 1.0.1's parallel signing), so the agent
// asks the token before it stops using it. A wrong PIN costs the token one more try; the right one costs nothing.
const pkcs11tool = require('./pkcs11ToolCommand');

//the check is one login, so a token that takes longer than this isn't answering
const CHECK_TIME_LIMIT = 10000;

//a wrong PIN shows as 'Login failed' from OpenSSL's PKCS#11 engine and as CKR_PIN_INCORRECT or CKR_PIN_LOCKED from native signing and pkcs11-tool
var isLoginFailure = function(err) {
    let message = String(err);
    return message.indexOf('Login failed') >= 0 || message.indexOf('CKR_PIN_INCORRECT') >= 0 || message.indexOf('CKR_PIN_LOCKED') >= 0;
}

//checks running now, by token: a second failure on the same token waits for the running check instead of spending another try
var running = {};

// callback(result, detail): result 'rejected' (the token refused the PIN), 'accepted' (it logged in) or 'unknown' (the check
// itself failed; detail says how). params: module, slotid (the token's slot), serial, pin
var checkPin = function(params, callback) {
    let id = params.module + ' ' + params.serial;
    if(running[id]) {
        running[id].push(callback);
        return;
    }
    running[id] = [callback];
    let finish = function(result, detail) {
        let callbacks = running[id];
        delete running[id];
        for(let i = 0; i < callbacks.length; i++) {
            callbacks[i](result, detail);
        }
    }
    if(!params.pin) {
        finish('unknown', 'the agent has no PIN for the token');
        return;
    }
    pkcs11tool.run(['--module', params.module, '--slot', String(params.slotid), '--login', '--pin', String(params.pin), '--list-objects', '--type', 'privkey'], { timeout: CHECK_TIME_LIMIT }, function(err, out) {
        let stderr = String((out && out.stderr) || '');
        if(out && out.exitcode === 0) {
            finish('accepted', '');
        } else if(isLoginFailure(stderr)) {
            finish('rejected', stderr.trim().split('\n')[0]);
        } else if(out && out.exitcode === null && !(err instanceof Error)) {
            finish('unknown', 'pkcs11-tool gave no answer in ' + CHECK_TIME_LIMIT / 1000 + ' s');
        } else {
            finish('unknown', (stderr.trim().split('\n')[0]) || String(err && err.message || err));
        }
    });
}

module.exports = {
    checkPin: checkPin,
    isLoginFailure: isLoginFailure
}
