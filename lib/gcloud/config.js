const yaml = require('js-yaml');
const fs = require('fs');

module.exports = {
    write: function(config, callback) {
        const yamlStr = yaml.dump(config);
        console.log(yamlStr);
        callback(false, yamlStr);
    }
}