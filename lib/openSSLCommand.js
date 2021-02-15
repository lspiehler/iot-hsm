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

var runOpenSSLCommand = function(cmd, callback) {
    const stdoutbuff = [];
    const stderrbuff = [];
    var terminate = false;
    
    if(cmd.indexOf('s_client') >= 0) {
        terminate = true;
    }
    
    const openssl = spawn( opensslbinpath, normalizeCommand(cmd) );
    
    openssl.stdout.on('data', function(data) {
        stdoutbuff.push(data.toString());
        /*//openssl.stdin.setEncoding('utf-8');
        setTimeout(function() {
            //openssl.stdin.write("QUIT\r");
            //console.log('QUIT\r\n');
            //openssl.stdin.end();
            openssl.kill();
        }, 1000);*/
        if(terminate) {
            //if(data.toString().indexOf('Verify return code: 0 (ok)') >= 0 ) {
            if(stdoutbuff.join('').toString().indexOf('Verify return code: ') >= 0 ) {
                openssl.kill();
            }
        }
    });

    /*openssl.stdout.on('end', function(data) {
        stderrbuff.push(data.toString());
    });*/
    
    openssl.stderr.on('data', function(data) {
        stderrbuff.push(data.toString());
    });
    
    openssl.on('exit', function(code) {
        if(terminate && code==null) {
            code = 0;
        }
        var out = {
            command: 'openssl ' + cmd,
            stdout: stdoutbuff.join(''),
            stderr: stderrbuff.join(''),
            exitcode: code
        }
        if (code != 0) {
            callback(stderrbuff.join(), out);
        } else {
            callback(false, out);
        }
    });
}

module.exports = {
    run: function(cmd, callback) {
        runOpenSSLCommand(cmd, function(err, out) {
            if(err) {
                callback(err, out);
            } else {
                callback(false, out);
            }
        });
    }
}