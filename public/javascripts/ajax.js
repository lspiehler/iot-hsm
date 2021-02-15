function postRequest(url, data, callback) {
    var request = new XMLHttpRequest();
    request.open('POST', url, true);
    request.setRequestHeader('Content-Type', 'application/json; charset=UTF-8');
    
    request.onload = function() {
        if (request.status >= 200 && request.status < 301) {
            // Success!
            var resp = JSON.parse(request.responseText);
            if(resp.error) {
                callback(resp.error, resp);
            } else if(resp.success==false) {
                callback(resp.message, resp);
            } else {
                callback(null, resp);
            }
            return;
            //var key = document.getElementById('key');
            //key.innerText = resp.command + '\r\n\r\n' + resp.key;
            //var csroptions = getCSRParams();
            //generateCSR(resp.key, csroptions);
        } else if(request.status == 401) {
            window.location = '/auth/login';
        } else if(request.status >= 400) {
            alert('Invalid response from the server');
        } else {
            // We reached our target server, but it returned an error
            var resp = JSON.parse(request.responseText);
            callback(resp.error, null);
            return;
        }
    };

    request.onerror = function() {
        callback('Communication error', null);
        return;
        // There was a connection error of some sort
    };

    request.send(JSON.stringify(data));
}

function getAPIRequest(url, callback) {
    var request = new XMLHttpRequest();
    request.open('GET', url, true);
    //request.setRequestHeader('Content-Type', 'application/json; charset=UTF-8');
    
    request.onload = function() {
        if (request.status >= 200 && request.status < 301) {
            // Success!
            var resp = JSON.parse(request.responseText);
            if(resp.error) {
                callback(resp.error, resp);
            } else if(resp.success==false) {
                callback(resp.message, resp);
            } else {
                callback(null, resp);
            }
            return;
            //var key = document.getElementById('key');
            //key.innerText = resp.command + '\r\n\r\n' + resp.key;
            //var csroptions = getCSRParams();
            //generateCSR(resp.key, csroptions);
        } else if(request.status == 301 || request.status == 302) {
            window.location = '/auth/login';
        } else if(request.status >= 400) {
            alert('Invalid response from the server');
        } else {
            // We reached our target server, but it returned an error
            var resp = JSON.parse(request.responseText);
            callback(resp.error, null);
            return;
        }
    };

    request.onerror = function() {
        callback('Communication error', null);
        return;
        // There was a connection error of some sort
    };

    request.send();
}