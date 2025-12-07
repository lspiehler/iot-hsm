const PubNub = require('pubnub');
const { v4: uuidv4 } = require('uuid');
var config = require('../config');
const statelib = require('./statelib');
var events = require('events');
var eventEmitter = new events.EventEmitter();

// const uuid = uuidv4();
var uuid;
// const uuid = 'c3e5d29a-1147-47fb-8085-744d104aaefd';
var publishKey;
var subscribeKey;
var pubnub;

module.exports = function(params) {
    //console.log(params);

    if(!uuid) {
        let state = statelib.get();
        if(state.hasOwnProperty('uuid')) {
            uuid = state.uuid;
            console.log('Using existing UUID: ' + uuid);
        } else {
            uuid = uuidv4();
            statelib.setUUID({uuid: uuid}, function(err, newstate) {
                if(err) {
                    console.log('Error setting UUID in state:');
                    console.log(err);
                } else {
                    console.log('Generated new UUID: ' + uuid);
                }
            });
        }
    }

    publishKey = params.publishKey;
    subscribeKey = params.subscribeKey;

    pubnub = new PubNub({
        publishKey: params.publishKey,
        subscribeKey: params.subscribeKey,
        uuid: uuid
    });

    pubnub.addListener({
        /*connect: function(connectEvent) {
            console.log(connectEvent);
        },*/
        status: function(statusEvent) {
            if (statusEvent.category === "PNConnectedCategory") {
                console.log(statusEvent);
                /*sendMessage({channel: "hello_world", message: {text: "Server is started!"}}, function(status, response) {
                    if(status.error) {
                        console.log(err);
                    } else {
                        console.log(response);
                        //console.log(status);
                    }
                });*/
            }
        },
        message: function(messageEvent) {
            //console.log(messageEvent.message.title);
            //console.log(pubnub);
            if(messageEvent.publisher==uuid) {
                //console.log('ignore messages from self');
            } else {
                /*console.log('here');
                console.log(messageEvent);
                sendMessage({channel: messageEvent.channel, message: {text: "Message received"}}, function(err, response) {
                    if(err) {
                        console.log(err);
                    } else {
                        console.log(response);
                    }
                });*/
                eventEmitter.emit('message', messageEvent);
            }
        },
        presence: function(presenceEvent) {
            // handle presence
            console.log(presenceEvent);
        }
    });

    this.unsubscribeAll = function() {
        console.log('unsubscribing');
        pubnub.unsubscribeAll();
    }

    this.subscribe = function(params) {
        subscribe(params);
    }

    this.getUUID = function() {
        return uuid;
    }

    this.event = eventEmitter;

    this.sendMessage = function(msg, callback) {
        //msg.meta.uuid = pubnub.getUUID();
        pubnub.publish(msg, function(status, response) {
            callback(status, response);
        });
    }

    var subscribe = function(params) {
        pubnub.subscribe({
            channels: params.channels
        });
    }

    subscribe(params);
}