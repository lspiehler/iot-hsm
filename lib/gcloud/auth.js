const { GoogleAuth } = require("google-auth-library");
const common = require('../common');

var auth;

var getToken = function(auth, callback) {
    auth.getClient()
        .then(client => {
            // console.log("Got client:", !!client);
            return client.getAccessToken();
        })
        .then(result => {
            if (!result || !result.token) {
                return callback(new Error("Failed to obtain token"), null);
            }

            callback(null, result.token);
        })
        .catch(err => {
            console.error("Error getting token:", err);
            callback(err, false);
        });
};

module.exports = {
    getToken: function(callback) {
        if (!auth) {

            var options = {
                host: 'metadata.google.internal',
                port: 80,
                method: 'GET'
            }

            common.request({protocol: 'http', options: options}, function(err, resp) {
                if (err) {
                    // console.log(err);
                    auth = new GoogleAuth({
                        scopes: ['https://www.googleapis.com/auth/cloud-platform'],
                        // keyFile: config.GOOGLE_APPLICATION_CREDENTIALS
                    });
                } else {
                    // console.log(resp);
                    auth = new GoogleAuth({
                        scopes: ['https://www.googleapis.com/auth/cloud-platform'],
                        keyFile: null
                    });
                }
                getToken(auth, function(err, token) {
                    if (err) {
                        auth = null;
                        callback(err, null);
                    } else {
                        // console.log(token);
                        callback(null, token);
                    }
                });
            });
            
        } else {
            getToken(auth, function(err, token) {
                if (err) {
                    auth = null;
                    callback(err, null);
                } else {
                    // console.log(token);
                    callback(null, token);
                }
            });
        }
    }
};