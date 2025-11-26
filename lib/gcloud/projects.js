const auth = require('./auth');
const common = require('../common');

module.exports = {
    get: function(callback) {
        auth.getToken(function(err, token) {
            if (err) {
                return callback(err, null);
            } else {
                // Make REST request to Cloud Resource Manager
                var options = {
                    host: 'cloudresourcemanager.googleapis.com',
                    port: 443,
                    path: '/v1/projects',
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + token
                    }
                }

                common.request({options: options}, function(err, resp) {
                    if (err) {
                        callback(err, resp);
                    } else {
                        // console.log(resp);
                        callback(false, resp.data);
                    }
                });
            }
        });
    }
}