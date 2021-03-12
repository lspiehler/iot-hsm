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
    var code;
    var exited = false;
    var stdoutrecvd = false;
    var stderrrecvd = true;

    if(params.cmd.indexOf(' -out ') >= 0) {
        //don't wait for stdout because none is expected
        stdoutrecvd = true;
    }

    var handleExit = function() {
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
    }
    
    try {
        const openssl = spawn( 'openssl', normalizeCommand(params.cmd), {cwd: params.cwd } );

        //console.log(openssl.pid);

        if(params.hasOwnProperty('stdin')) {
            if(params.stdin) {
                openssl.stdin.write(params.stdin);
                openssl.stdin.end();
            }
        }
        
        openssl.stdout.on('data', function(data) {
            stdoutrecvd = true;
            stdoutbuff.push(data);
            if(exited && code == 0) {
                handleExit();
            }
        });

        openssl.on('error', function(err) {
            console.log(err);
            callback(err, false);
            return;
        });
        
        openssl.stderr.on('data', function(data) {
            stderrrecvd = true;
            stderrbuff.push(data);
            if(exited && code != 0) {
                handleExit();
            }
        });
        
        openssl.on('exit', function(ecode) {
            exited = true;
            code = ecode;
            if(stdoutrecvd && ecode == 0) {
                handleExit();
            }

            if(stderrrecvd && ecode != 0) {
                handleExit();
            }
            
        });
    } catch(e) {
        console.log(e);
        callback(e, false);
        return;
    }
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