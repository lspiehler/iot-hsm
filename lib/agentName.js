// The name its owner gave the appliance (AGENT_NAME), as the platform accepts it (pkiaas lib/pubnub/offerDetails.js checks
// the same): 1 to 64 letters, digits, spaces and . _ - ( ) # : / @, without spaces around it. The agent (lib/agentInfo.js)
// and the installer (scripts/setup_ubuntu.sh) both check names here, so they never disagree.
const NAME = /^[\p{L}\p{N} ._()#:\/@-]{1,64}$/u;

// the name without spaces around it, or false when it's unset or isn't a name the platform accepts
module.exports = function agentName(value) {
    let name = typeof(value) == 'string' ? value.trim() : '';
    return NAME.test(name) ? name : false;
}
