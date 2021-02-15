const PubNub = require('pubnub');
const { v4: uuidv4 } = require('uuid');
var config = require('../config');

//const uuid = config.getCertInfo().attributes.Thumbprint.split(':').join('').toLowerCase();
const uuid = uuidv4();
var initialized = false;

const pubnub = new PubNub({
    publishKey: "pub-c-614b38aa-8031-404c-bd03-4b96986709c5",
    subscribeKey: "sub-c-14348a82-6977-11eb-95b1-4ae0cccec446",
    uuid: uuid
});

function sendMessage(msg, callback) {
    pubnub.publish(msg, function(status, response) {
        callback(status, response);
    });
}

pubnub.addListener({
    /*connect: function(connectEvent) {
        console.log(connectEvent);
    },*/
    status: function(statusEvent) {
        if (statusEvent.category === "PNConnectedCategory") {
            sendMessage({channel: "hello_world", message: {text: "Server is started!"}}, function(status, response) {
                if(status.error) {
                    console.log(err);
                } else {
                    console.log(response);
                    //console.log(status);
                }
            });
        }
    },
    message: function(messageEvent) {
        //console.log(messageEvent.message.title);
        //console.log(pubnub);
        if(messageEvent.publisher==uuid) {
            console.log('ignore messages from self');
        } else {
            console.log(messageEvent);
            sendMessage({channel: "hello_world", message: {text: "Message received"}}, function(err, response) {
                if(err) {
                    console.log(err);
                } else {
                    console.log(response);
                }
            });
        }
    },
    presence: function(presenceEvent) {
        // handle presence
        console.log(presenceEvent);
    }
});

console.log("Subscribing..");

pubnub.subscribe({
    channels: ["hello_world"]
});