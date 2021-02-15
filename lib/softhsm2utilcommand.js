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

var softHSM2UtilCommand = function(cmd, callback) {
    const stdoutbuff = [];
    const stderrbuff = [];
    var terminate = false;
    
    if(cmd.indexOf('s_client') >= 0) {
        terminate = true;
    }
    
    const softHSM2Util = spawn( 'softhsm2-util', normalizeCommand(cmd) );
    
    softHSM2Util.stdout.on('data', function(data) {
        stdoutbuff.push(data.toString());
        /*//pkcs11tool.stdin.setEncoding('utf-8');
        setTimeout(function() {
            //pkcs11tool.stdin.write("QUIT\r");
            //console.log('QUIT\r\n');
            //pkcs11tool.stdin.end();
            pkcs11tool.kill();
        }, 1000);*/
        if(terminate) {
            //if(data.toString().indexOf('Verify return code: 0 (ok)') >= 0 ) {
            if(stdoutbuff.join('').toString().indexOf('Verify return code: ') >= 0 ) {
                softHSM2Util.kill();
            }
        }
    });

    /*pkcs11tool.stdout.on('end', function(data) {
        stderrbuff.push(data.toString());
    });*/
    
    softHSM2Util.stderr.on('data', function(data) {
        stderrbuff.push(data.toString());
    });
    
    softHSM2Util.on('exit', function(code) {
        if(terminate && code==null) {
            code = 0;
        }
        var out = {
            command: 'pkcs11-tool ' + cmd,
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
        softHSM2UtilCommand(cmd, function(err, out) {
            if(err) {
                callback(err, out);
            } else {
                callback(false, out);
            }
        });
    }
}