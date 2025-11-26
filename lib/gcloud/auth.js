const { GoogleAuth } = require("google-auth-library");
const config = require('../../config');

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
            auth = new GoogleAuth({
                keyFile: config.GOOGLE_APPLICATION_CREDENTIALS,
                scopes: ['https://www.googleapis.com/auth/cloud-platform']
            });

            getToken(auth, function(err, token) {
                if (err) {
                    callback(err, null);
                } else {
                    // console.log(token);
                    callback(null, token);
                }
            });
            
        } else {
            getToken(auth, function(err, token) {
                if (err) {
                    callback(err, null);
                } else {
                    // console.log(token);
                    callback(null, token);
                }
            });
        }
    }
};