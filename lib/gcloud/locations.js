const auth = require('./auth');
const common = require('../common');

module.exports = {
    get: function(params, callback) {
        auth.getToken(function(err, token) {
            if (err) {
                return callback(err, null);
            } else {
                // Make REST request to Cloud KMS
                var options = {
                    host: 'cloudkms.googleapis.com',
                    port: 443,
                    path: '/v1/projects/' + params.project + '/locations',
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