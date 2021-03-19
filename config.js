require('dotenv').config();

module.exports = {
	PLATFORMFQDN: process.env.PLATFORMFQDN || 'pkiaas.io',
	USERPIN: process.env.USERPIN || '123456',
	SOPIN: process.env.SOPIN || '010203040506070801020304050607080102030405060708',
	LIB: process.env.LIB || '/usr/lib'
}