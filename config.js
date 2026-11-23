require('dotenv').config();

module.exports = {
	PLATFORMFQDN: process.env.PLATFORMFQDN || 'pkiaas.io',
	USERPIN: process.env.USERPIN || '123456',
	SOPIN: process.env.SOPIN || '010203040506070801020304050607080102030405060708',
	LIB: process.env.LIB || '/usr/lib',
	LISTENIP: process.env.LISTENIP || '0.0.0.0',
	PORT: process.env.PORT || 3000,
	STATEDIR: process.env.STATEDIR || '/var/node/iot-hsm/state',
	GOOGLE_APPLICATION_CREDENTIALS: process.env.GOOGLE_APPLICATION_CREDENTIALS || '/var/node/iot-hsm/state/gcloud.json',
	KMS_PKCS11_CONFIG: process.env.KMS_PKCS11_CONFIG || '/var/node/iot-hsm/tmp/pkcs11-kms.yml',
	CHANNELCERTMINUTES: process.env.CHANNELCERTMINUTES || 720,
	GOOGLE_KMS_CONCURRENCY: process.env.GOOGLE_KMS_CONCURRENCY || 4,
	SOFTHSM_CONCURRENCY: process.env.SOFTHSM_CONCURRENCY || 2,
	NATIVESIGNING: process.env.NATIVESIGNING || false,
	// seconds a signature may run before the agent checks the token's PIN (one may be hanging on a rejected PIN)
	SIGNATURE_TIME_LIMIT: process.env.SIGNATURE_TIME_LIMIT || 15,
	// the name the platform shows for this appliance instead of its ID; none by default (never the hostname)
	AGENT_NAME: process.env.AGENT_NAME || ''
}