const { spawn } = require( 'child_process' );

var normalizeCommand = function(command) {
    let cmd = command.split(' ');
    let outcmd = [];
    let cmdbuffer = [];
    for(let i = 0; i <= cmd.length - 1; i++) {
        if(cmd[i].charAt(cmd[i].length - 1) == '\\') {
            cmdbuffer.push(cmd[i].replace('\\', ''));
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

//pass PINs through the environment ('env:NAME' is read by pkcs11-tool) so they don't show in the process list
var hidePins = function(args) {
    let env = Object.assign({}, process.env);
    for(let i = 0; i < args.length - 1; i++) {
        if(args[i] == '--pin' || args[i] == '--so-pin' || args[i] == '--new-pin') {
            env['IOTHSM_PIN_' + i] = args[i + 1];
            args[i + 1] = 'env:IOTHSM_PIN_' + i;
        }
    }
    return env;
}

//cmd is a command line split on spaces, or an array of arguments; options.timeout (ms) stops pkcs11-tool when it runs longer
var runPKCS11ToolCommand = function(cmd, options, callback) {
    //console.log(normalizeCommand(cmd));
    const stdoutbuff = [];
    const stderrbuff = [];
    var terminate = false;
    var finished = false;
    
    const command = 'pkcs11-tool ' + (Array.isArray(cmd) ? cmd.join(' ') : cmd);
    if(command.indexOf('s_client') >= 0) {
        terminate = true;
    }
    
    const args = Array.isArray(cmd) ? cmd.slice() : normalizeCommand(cmd);
    const pkcs11tool = spawn( 'pkcs11-tool', args, { env: hidePins(args), timeout: options.timeout } );

    var finish = function(err, out) {
        if(!finished) {
            finished = true;
            callback(err, out);
        }
    }

    //without this, a missing pkcs11-tool would end the agent
    pkcs11tool.on('error', function(err) {
        finish(err, { command: command, stdout: stdoutbuff.join(''), stderr: stderrbuff.join(''), exitcode: null });
    });
    
    pkcs11tool.stdout.on('data', function(data) {
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
                pkcs11tool.kill();
            }
        }
    });

    /*pkcs11tool.stdout.on('end', function(data) {
        stderrbuff.push(data.toString());
    });*/
    
    pkcs11tool.stderr.on('data', function(data) {
        stderrbuff.push(data.toString());
    });
    
    //'close' comes after the output is read, so an error carries its text
    pkcs11tool.on('close', function(code) {
        if(terminate && code==null) {
            code = 0;
        }
        var out = {
            command: command,
            stdout: stdoutbuff.join(''),
            stderr: stderrbuff.join(''),
            exitcode: code
        }
        if (code != 0) {
            finish(stderrbuff.join(), out);
        } else {
            finish(false, out);
        }
    });
}

module.exports = {
    run: function(cmd, options, callback) {
        if(typeof options == 'function') {
            callback = options;
            options = {};
        }
        runPKCS11ToolCommand(cmd, options, function(err, out) {
            if(err) {
                callback(err, out);
            } else {
                callback(false, out);
            }
        });
    }
}