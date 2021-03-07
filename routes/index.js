var express = require('express');
var router = express.Router();
var openssl = require('../lib/openssl');
var config = require('../config');
var slotlib = require('../lib/slotlib');
const apiResponse = require('../api/apiResponse');

/* GET home page. */
router.get('/', function(req, res, next) {
	slotlib.getSlots(false, function(err, slots) {
		//console.log(slots);
		res.render('index', { userpin: config.USERPIN, sopin: config.SOPIN, title: 'Express', slots: slots, slotstring: JSON.stringify(slots) });
	});
});

router.get('/getCert', function(req, res, next) {
	res.json(config.getCertInfo());
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

module.exports = router;
