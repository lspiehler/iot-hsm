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
var reconnecttimer = false;
//seconds to wait before subscribing again after PubNub gave up
const reconnectdelay = 60;

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
                //the event lists the channel IDs, which act as secrets; don't log them
                //pubnub 11+ (event engine) reports affectedChannels instead of subscribedChannels
                console.log('Connected to PubNub (' + statusEvent.affectedChannels.length + ' channels)');
                /*sendMessage({channel: "hello_world", message: {text: "Server is started!"}}, function(status, response) {
                    if(status.error) {
                        console.log(err);
                    } else {
                        console.log(response);
                        //console.log(status);
                    }
                });*/
            } else {
                //network problems, reconnects and subscription changes; the event lists channel IDs, so log only the category
                console.log(new Date + ' - PubNub status: ' + statusEvent.category);
                //after a few failed retries PubNub stops subscribing and nothing restarts it, so the agent would stop receiving requests until it is restarted
                if((statusEvent.category === 'PNDisconnectedUnexpectedlyCategory' || statusEvent.category === 'PNConnectionErrorCategory') && !reconnecttimer) {
                    console.log('PubNub stopped trying to connect. Trying again in ' + reconnectdelay + ' seconds...');
                    reconnecttimer = setTimeout(function() {
                        reconnecttimer = false;
                        console.log(new Date + ' - Reconnecting to PubNub...');
                        pubnub.reconnect();
                    }, reconnectdelay * 1000);
                }
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
            console.log('PubNub presence event: ' + presenceEvent.action);
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