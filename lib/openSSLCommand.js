const { spawn } = require( 'child_process' );

var normalizeCommand = function(command) {
    let cmd = command.split(' ');
    let outcmd = [];
    let cmdbuffer = [];
    for(let i = 0; i <= cmd.length - 1; i++) {
        if(cmd[i].charAt(cmd[i].length - 1) == '\\') {
            cmdbuffer.push(cmd[i]);
        } else {
            if(cmdbuffer.length > 0) {
                outcmd.push(cmdbuffer.join(' ') + ' ' + cmd[i]);
                cmdbuffer.length = 0;
            } else {
                outcmd.push(cmd[i]);
            }
        }
    }
    return outcmd;
}

var runOpenSSLCommand = function(params, callback) {
    const stdoutbuff = [];
    const stderrbuff = [];
    
    const openssl = spawn( 'openssl', normalizeCommand(params.cmd) );

    if(params.hasOwnProperty('stdin')) {
        if(params.stdin) {
            openssl.stdin.write(params.stdin);
            openssl.stdin.end();
        }
    }
    
    openssl.stdout.on('data', function(data) {
        stdoutbuff.push(data);
    });

    /*openssl.stdout.on('end', function(data) {
        stderrbuff.push(data.toString());
    });*/
    
    openssl.stderr.on('data', function(data) {
        stderrbuff.push(data);
    });
    
    openssl.on('exit', function(code) {
        var out = {
            command: 'openssl ' + params.cmd,
            stdout: Buffer.concat(stdoutbuff),
            stderr: Buffer.concat(stderrbuff),
            exitcode: code
        }
        if (code != 0) {
            callback(Buffer.concat(stderrbuff).toString(), out);
        } else {
            callback(false, out);
        }
    });
}

module.exports = {
    run: function(params, callback) {
        runOpenSSLCommand(params, function(err, out) {
            if(err) {
                callback(err, out);
            } else {
                callback(false, out);
            }
        });
    }
}