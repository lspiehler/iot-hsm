var pkcs11tool = require('../lib/pkcs11ToolCommand');

let cmd = ['--module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --login --login-type so --so-pin 010203040506070801020304050607080102030405012345 --slot 0x3df9b5 --id 01 --delete-object --type cert'];
console.log(cmd.join(' '));
pkcs11tool.run(cmd.join(' '), function(err, out) {
    console.log(out);
    if(err) {
        callback(err, false);
    } else {
        console.log(out.stdout);
    }
});