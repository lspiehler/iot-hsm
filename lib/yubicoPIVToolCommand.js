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

var runYubicoPIVToolCommand = function(params, callback) {
    //console.log(normalizeCommand(cmd));
    const stdoutbuff = [];
    const stderrbuff = [];
    var terminate = false;
    
    const yubicopivtool = spawn( 'yubico-piv-tool', normalizeCommand(params.cmd) );

    if(params.hasOwnProperty('stdin')) {
        if(params.stdin) {
            yubicopivtool.stdin.write(params.stdin);
            yubicopivtool.stdin.end();
        }
    }
    
    yubicopivtool.stdout.on('data', function(data) {
        stdoutbuff.push(data);
    });

    /*yubicopivtool.stdout.on('end', function(data) {
        stderrbuff.push(data.toString());
    });*/
    
    yubicopivtool.stderr.on('data', function(data) {
        stderrbuff.push(data);
    });
    
    yubicopivtool.on('exit', function(code) {
        if(terminate && code==null) {
            code = 0;
        }
        var out = {
            command: 'yubico-piv-tool ' + params.cmd,
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
    run: function(cmd, callback) {
        runYubicoPIVToolCommand(cmd, function(err, out) {
            if(err) {
                callback(err, out);
            } else {
                callback(false, out);
            }
        });
    }
}