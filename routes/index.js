var express = require('express');
var router = express.Router();
var config = require('../config');
var slotlib = require('../lib/slotlib');
var iothsm = require('../lib/IoTHSM');
const apiResponse = require('../api/apiResponse');
const wizardkey = require('../api/wizard-key');
const wizardselfsigned = require('../api/wizard-selfsigned');
const wizardcsr = require('../api/wizard-csr');
const wizardimport = require('../api/wizard-import');
const clearslot = require('../api/clearSlot');
var title = 'IoT-HSM';
var pinlib = require('../lib/pin');
const common = require('../lib/common');

const gcloud = require('../lib/gcloud');

/* GET home page. */
router.get('/', function(req, res, next) {
	slotlib.getSlots(false, function(err, slots) {
		//console.log(slots);
		if(err) {
			res.status(400).send(err);
		} else {
			if(slots.state == 'initializing') {
				res.redirect('/initializing');
			} else {
				let iot = iothsm.getSlots();
				//console.log(iot);
				res.render('index', { title: title, iot: iot, iotstring: JSON.stringify(iot), slots: slots, slotstring: JSON.stringify(slots) });
			}
		}
	});
});

router.get('/api/google/projects', function(req, res, next) {
	gcloud.projects.get(function(err, projects) {
		if(err) {
			res.json({
				result: 'error',
				error: err.toString()
			});
		} else {
			// console.log(JSON.stringify(projects, null, 2));
			if(projects.hasOwnProperty('error')) {
				res.json({
					result: 'error',
					error: projects.error.message
				});
				return;
			} else {
				res.json({
					result: 'success',
					projects: projects.projects
				});
			}
		}
	});
});

router.get('/api/google/:project/locations', function(req, res, next) {
	gcloud.locations.get({project: req.params.project}, function(err, locations) {
		if(err) {
			res.json({
				result: 'error',
				error: err.toString()
			});
		} else {
			// console.log(locations);
			res.json({
				result: 'success',
				locations: locations.locations
			});
		}
	});
});

router.get('/api/google/:project/:location/keyrings', function(req, res, next) {
	gcloud.keyrings.get({project: req.params.project, location: req.params.location}, function(err, keyrings) {
		if(err) {
			res.json({
				result: 'error',
				error: err.toString()
			});
		} else {
			// console.log(keyrings);
			let krs = [];
			if(keyrings.hasOwnProperty('keyRings')) {
				krs = keyrings.keyRings;
			}
			res.json({
				result: 'success',
				keyrings: krs
			});
		}
	});
});

router.get('/test', function(req, res, next) {
	gcloud.projects.get(function(err, projects) {
		if(err) {
			res.status(400).send(err);
		} else {
			// console.log(projects.projects[0].name);
			gcloud.locations.get({project: projects.projects[0].name}, function(err, locations) {
				if(err) {
					res.status(400).send(err);
				} else {
					let validlocations = [];
					for(let i = 0; i <= locations.locations.length - 1; i++) {
						if(locations.locations[i].metadata.hsmAvailable) {
							validlocations.push(locations.locations[i].locationId);
						}
					}
					gcloud.keyrings.get({project: projects.projects[0].name, location: 'us-east1'}, function(err, keyrings) {
						if(err) {
							res.status(400).send(err);
						} else {
							gcloud.tokens.get(function(err, tokens) {
								if (err) {
									res.status(400).send(err);
								} else {
									res.json({
										projects: projects,
										locations: validlocations,
										keyrings: keyrings,
										tokens: tokens
									});
								}
							});
						}
					});
				}
			});
		}
	});
});

router.get('/initializing', function(req, res, next) {
	slotlib.getSlots(false, function(err, slots) {
		if(slots.state == 'initializing') {
			let iot = iothsm.getSlots();
			res.render('initializing', { title: title, iot: iot, iotstring: JSON.stringify(iot), slots: slots, slotstring: JSON.stringify(slots) });
		} else {
			res.redirect('/');
		}
	});
});

router.get('/expert', function(req, res, next) {
	slotlib.getSlots(false, function(err, slots) {
		//console.log(slots);
		let iot = iothsm.getSlots();
		res.render('expert', { title: title, iot: iot, iotstring: JSON.stringify(iot), slots: slots, slotstring: JSON.stringify(slots) });
	});
});

router.get('/getCert', function(req, res, next) {
	res.json(config.getCertInfo());
});

router.get('/wizard/key/:serial', function(req, res, next) {
	slotlib.getSlots(false, function(err, slots) {
		// console.log(slots);
		if(err) {
			res.status(400).send(err);
		} else {
			let iot = iothsm.getSlots();
			res.render('wizard/key', { title: title, iot: iot, iotstring: JSON.stringify(iot), serial: req.params.serial, slotstring: JSON.stringify(slots) });
		}
	});
});

router.get('/wizard/google/:serial', function(req, res, next) {
	slotlib.getSlots(false, function(err, slots) {
		// console.log(slots);
		if(err) {
			res.status(400).send(err);
		} else {
			let iot = iothsm.getSlots();
			res.render('wizard/google', { title: title, iot: iot, iotstring: JSON.stringify(iot), serial: req.params.serial, slotstring: JSON.stringify(slots) });
		}
	});
});

router.get('/wizard/provision/:serial/:slotid', function(req, res, next) {
	slotlib.getSlots(false, function(err, slots) {
		//console.log(slots);
		if(err) {
			res.status(400).send(err);
		} else {
			let iot = iothsm.getSlots();
			res.render('wizard/choices', { title: title, iot: iot, iotstring: JSON.stringify(iot), serial: req.params.serial, slotid: req.params.slotid, slotstring: JSON.stringify(slots) });
		}
	});
});

router.get('/googlekms', function(req, res, next) {
	var options = {
		host: 'metadata.google.internal',
		port: 80,
		method: 'GET'
	}

	let gcp = false;

	common.request({protocol: 'http', options: options}, function(err, resp) {
		if(err) {
			gcp = false;
		} else {
			gcp = true;
		}
		slotlib.getSlots(false, function(err, slots) {
			//console.log(slots);
			if(err) {
				res.status(400).send(err);
			} else {
				let iot = iothsm.getSlots();
				res.render('googlekms', { title: title, iot: iot, iotstring: JSON.stringify(iot), serial: req.params.serial, slotid: req.params.slotid, slotstring: JSON.stringify(slots), gcp: gcp });
			}
		});
	});
});

router.get('/api/gcloud/tokens', function(req, res, next) {
	gcloud.tokens.get(function(err, tokens) {
		if (err) {
			res.status(400).send(err);
		} else {
			res.json({
				tokens: tokens
			});
		}
	});
});

router.get('/api/reload', function(req, res, next) {
	slotlib.getSlots(true, function(err, slots) {
		if(err) {
			res.json(apiResponse.create({
				success: false,
				message: err,
				data: null
			}));
		} else {
			res.json(apiResponse.create({
				success: true,
				message: 'Successful API response',
				data: slots
			}));
		}
	});
});

router.post('/api/pkcs11/delete', function(req, res, next) {
	//console.log(req.body);
	slotlib.deleteObject(req.body, function(err, resp) {
		if(err) {
			res.json(apiResponse.create({
				success: false,
				message: err,
				data: null
			}));
		} else {
			res.json(apiResponse.create({
				success: true,
				message: resp,
				data: req.body
			}));
		}
	});
});

router.get('/api/pkcs11/slotstatus', function(req, res, next) {
	slotlib.getSlots(false, function(err, slots) {
		if(err) {
			res.json(apiResponse.create({
				success: false,
				message: err,
				data: null
			}));
		} else {
			res.json(apiResponse.create({
				success: true,
				message: 'Successful API response',
				data: slots
			}));
		}
	});
});

router.post('/api/softhsm2/delete', function(req, res, next) {
	//console.log(req.body);
	slotlib.deleteHSM2Slot(req.body, function(err, resp) {
		if(err) {
			res.json(apiResponse.create({
				success: false,
				message: err,
				data: null
			}));
		} else {
			res.json(apiResponse.create({
				success: true,
				message: resp,
				data: req.body
			}));
		}
	});
});

router.post('/api/pkcs11/generatekey', function(req, res, next) {
	//console.log(req.body);
	slotlib.generateKeyPair(req.body, function(err, resp) {
		if(err) {
			res.json(apiResponse.create({
				success: false,
				message: err,
				data: {}
			}));
		} else {
			res.json(apiResponse.create({
				success: true,
				message: resp,
				data: req.body
			}));
		}
	});
});

router.post('/api/pkcs11/clearslot', function(req, res, next) {
	//console.log(req.body);
	clearslot.handler(req.body, function(err, resp) {
		if(err) {
			res.json(apiResponse.create({
				success: false,
				message: err,
				data: {}
			}));
		} else {
			res.json(apiResponse.create({
				success: true,
				message: resp,
				data: req.body
			}));
		}
	});
});

router.post('/api/pkcs11/generateselfsigned', function(req, res, next) {
	//console.log(req.body);
	slotlib.generateSelfSigned(req.body, function(err, resp) {
		if(err) {
			res.json(apiResponse.create({
				success: false,
				message: err,
				data: {}
			}));
		} else {
			res.json(apiResponse.create({
				success: true,
				message: resp,
				data: req.body
			}));
		}
	});
});

router.post('/api/pkcs11/importkey', function(req, res, next) {
	//console.log(req.body);
	slotlib.importPrivateKey(req.body, function(err, resp) {
		if(err) {
			res.json(apiResponse.create({
				success: false,
				message: err,
				data: {}
			}));
		} else {
			res.json(apiResponse.create({
				success: true,
				message: resp,
				data: req.body
			}));
		}
	});
});

router.post('/api/pkcs11/importcertificate', function(req, res, next) {
	//console.log(req.body);
	slotlib.importCertificate(req.body, function(err, resp) {
		if(err) {
			res.json(apiResponse.create({
				success: false,
				message: err,
				data: {}
			}));
		} else {
			res.json(apiResponse.create({
				success: true,
				message: resp,
				data: req.body
			}));
		}
	});
});

router.post('/api/pkcs11/generatecsr', function(req, res, next) {
	//console.log(req.body);
	slotlib.generateCSR(req.body, function(err, resp) {
		if(err) {
			res.json(apiResponse.create({
				success: false,
				message: err,
				data: {}
			}));
		} else {
			res.json(apiResponse.create({
				success: true,
				message: resp,
				data: req.body
			}));
		}
	});
});

router.post('/api/pkcs11/signcsr', function(req, res, next) {
	//console.log(req.body);
	//res.json({});
	slotlib.signCSR(req.body, function(err, resp) {
		if(err) {
			res.json(apiResponse.create({
				success: false,
				message: err,
				data: {}
			}));
		} else {
			res.json(apiResponse.create({
				success: true,
				message: resp,
				data: req.body
			}));
		}
	});
});

router.post('/api/softhsm2/create', function(req, res, next) {
	//console.log(req.body);
	if(req.body.label == '' || req.body.label == false || req.body.label == null) {
		res.json(apiResponse.create({
			success: false,
			message: 'You must enter a label',
			data: {}
		}));
		return;
	}

	if(req.body.pin===false) {
		req.body.pin = '123456';
	}

	if(req.body.pin===false) {
		req.body.pin = '010203040506070801020304050607080102030405060708';
	}

	slotlib.createHSM2Slot(req.body, function(err, resp) {
		if(err) {
			res.json(apiResponse.create({
				success: false,
				message: err,
				data: {}
			}));
		} else {
			res.json(apiResponse.create({
				success: true,
				message: resp,
				data: req.body
			}));
		}
	});
});

router.post('/api/wizard/key', function(req, res, next) {
	//console.log(req.body);
	//res.json({});
	wizardkey.handler(req.body, function(err, resp) {
		if(err) {
			res.json(apiResponse.create({
				success: false,
				message: err,
				data: {}
			}));
		} else {
			res.json(apiResponse.create({
				success: true,
				message: resp,
				data: req.body
			}));
		}
	});
});

router.post('/api/wizard/selfsigned', function(req, res, next) {
	// console.log(req.body);
	//res.json({});
	wizardselfsigned.handler(req.body, function(err, resp) {
		if(err) {
			res.json(apiResponse.create({
				success: false,
				message: err,
				data: {}
			}));
		} else {
			res.json(apiResponse.create({
				success: true,
				message: resp,
				data: resp
			}));
		}
	});
});

router.post('/api/wizard/csr', function(req, res, next) {
	//console.log(req.body);
	//res.json({});
	wizardcsr.handler(req.body, function(err, resp) {
		//console.log(resp);
		if(err) {
			res.json(apiResponse.create({
				success: false,
				message: err,
				data: {}
			}));
		} else {
			res.json(apiResponse.create({
				success: true,
				message: 'Successful API response',
				data: resp
			}));
		}
	});
});

router.post('/api/wizard/import', function(req, res, next) {
	//console.log(req.body);
	//res.json({});
	wizardimport.handler(req.body, function(err, resp) {
		//console.log(resp);
		if(err) {
			res.json(apiResponse.create({
				success: false,
				message: err,
				data: {}
			}));
		} else {
			res.json(apiResponse.create({
				success: true,
				message: 'Successful API response',
				data: resp
			}));
		}
	});
});

router.post('/api/pin/set', function(req, res, next) {
	pinlib.setPins(req.body, function(err, resp) {
		//console.log(resp);
		if(err) {
			res.json(apiResponse.create({
				success: false,
				message: err,
				data: {}
			}));
		} else {
			res.json(apiResponse.create({
				success: true,
				message: 'Successful API response',
				data: resp
			}));
		}
	});
});

module.exports = router;
