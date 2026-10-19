// Live check for native signing (NATIVESIGNING, node-pki-signer) on a real token. Each request is signed
// twice with the same key by slotlib.signCSR: once as before, running OpenSSL through node-openssl-cert2,
// and once with NATIVESIGNING on. The two certificates must be identical apart from the serial number and
// the signature value, and node-pki-signer must have signed natively (no fallback logged).
//
// Runs only when the LIVE_* variables are set, as the agent's user on a device with the token:
//   PKCS#11 (YubiKey, SoftHSM): LIVE_PKCS11_MODULE, LIVE_PKCS11_SERIAL, LIVE_PKCS11_OBJECTID,
//     LIVE_PKCS11_CA (the CA certificate's PEM file), LIVE_PKCS11_PIN
//   Google Cloud KMS: LIVE_KMS_OBJECTID, LIVE_KMS_CA, GOOGLE_APPLICATION_CREDENTIALS, KMS_PKCS11_CONFIG;
//     LIVE_KMS_SERIAL (default 0000000000000000). The key version is found from KMS_PKCS11_CONFIG's key rings.
// Every KMS case costs two asymmetricSign calls, so the KMS suite runs only a few cases.
// The certificates it signs are thrown away, and the PIN is never printed.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { X509Certificate } = require('node:crypto');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

// slotlib reads the CA key's allowed mechanisms from the state; an empty state gives sha256, as for the
// YubiKey and KMS keys the agent holds
process.env.STATEDIR = fs.mkdtempSync(path.join(os.tmpdir(), 'native-signing-state-'));
const config = require('../config');
const slotlib = require('../lib/slotlib');
const openssl2 = require('../lib/openssl2');
const common = require('../lib/common');
const { shadowCASignCSR } = require('node-pki-signer');

const run = promisify(execFile);
const signCSR = promisify(slotlib.signCSR);

const KMS_MODULE = '/usr/lib/kms/libkmsp11.so';

/** A CSR with a new P-256 key, like the enrollment clients send. */
async function newCSR(subject) {
    const keyfile = path.join(process.env.STATEDIR, 'csr.key');
    const { stdout } = await run('openssl', ['req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
        '-nodes', '-keyout', keyfile, '-utf8', '-subj', subject]);
    fs.rmSync(keyfile);
    return stdout;
}

// validity as pkiaas sends it: now - 5 minutes to now + days
function dates(days) {
    const now = Date.now();
    return { startdate: new Date(now - 5 * 60 * 1000), enddate: new Date(now + days * 24 * 60 * 60 * 1000) };
}

const urls = {
    authorityInfoAccess: { caIssuers: ['http://certs.example.net/AbCdEf1234/TestCAca.crt'], OCSP: ['http://ocsp.example.net'] },
    crlDistributionPoints: ['http://crl.example.net/AbCdEf1234/TestCA.crl'],
    policies: [
        { policyIdentifier: '2.5.29.32.0', CPS: ['https://example.net/AbCdEf1234/CPS'] },
        { policyIdentifier: '2.23.140.1.2.1' },
    ],
};

// the options pkiaas sends the agent (lib/template/processTemplate.js, lib/ca/createServiceCerts.js)
const cases = {
    'web server (the SCEP e2e template)': {
        subject: '/C=US/ST=Louisiana/L=Slidell/CN=device.example.com',
        options: () => ({
            subject: { countryName: 'US', stateOrProvinceName: 'Louisiana', localityName: 'Slidell', commonName: 'device.example.com' },
            extensions: {
                keyUsage: { usages: ['digitalSignature', 'keyEncipherment'], critical: true },
                extendedKeyUsage: { usages: ['serverAuth', 'clientAuth'] },
                SANs: { DNS: ['device.example.com', 'www.device.example.com'], IP: ['198.51.100.7'] },
                basicConstraints: { critical: true, CA: false },
                ...urls,
            },
            ...dates(365),
        }),
    },
    'OCSP service certificate': {
        subject: '/CN=PKIaaS.io OCSP Responder/C=US',
        options: () => ({
            subject: { commonName: 'PKIaaS.io OCSP Responder', countryName: 'US' },
            extensions: {
                basicConstraints: { critical: true, CA: false },
                keyUsage: { critical: true, usages: ['digitalSignature'] },
                extendedKeyUsage: { usages: ['OCSPSigning'] },
                customOIDs: [{ OID: '1.3.6.1.5.5.7.48.1.5', value: 'ASN1:NULL' }],
            },
            ...dates(365),
        }),
    },
    'timestamp service certificate': {
        subject: '/CN=PKIaaS.io Timestamp Responder/C=US',
        options: () => ({
            subject: { commonName: 'PKIaaS.io Timestamp Responder', countryName: 'US' },
            extensions: {
                keyUsage: { critical: true, usages: ['digitalSignature'] },
                extendedKeyUsage: { critical: true, usages: ['timeStamping'] },
                basicConstraints: { CA: false, critical: true },
            },
            ...dates(3650),
        }),
    },
    'SCEP RA service certificate (empty usages)': {
        subject: '/C=US',
        options: () => ({
            subject: { countryName: 'US' },
            extensions: { keyUsage: { critical: false, usages: [] }, extendedKeyUsage: { critical: false, usages: [] } },
            ...dates(365),
        }),
    },
    'subject with / + \\ and quotes': {
        subject: '/C=US/CN=x',
        options: () => ({
            subject: { countryName: 'US', organizationName: 'Ops/Infra + "Lab" \\ A&B', commonName: 'odd.example.com' },
            extensions: { basicConstraints: { critical: true, CA: false }, SANs: { DNS: ['odd.example.com'] } },
            ...dates(30),
        }),
    },
    'non-ASCII subject, SANs and UPN': {
        subject: '/C=US/CN=x',
        options: () => ({
            subject: { countryName: 'US', organizationName: 'Société 日本語 مثال', commonName: '😊.example' },
            extensions: {
                basicConstraints: { critical: true, CA: false },
                SANs: { DNS: ['😊.example', '中文.example'], email: ['josé@例え.example'], otherName: ['msUPN;UTF8:josé😊@例え.example'] },
            },
            ...dates(30),
        }),
    },
    'CT precertificate (poison)': {
        subject: '/C=US/CN=ct.example.com',
        options: () => ({
            subject: { countryName: 'US', commonName: 'ct.example.com' },
            extensions: {
                keyUsage: { usages: ['digitalSignature', 'keyEncipherment'], critical: true },
                extendedKeyUsage: { usages: ['serverAuth'] },
                SANs: { DNS: ['ct.example.com'] },
                basicConstraints: { critical: true, CA: false },
                ...urls,
                customOIDs: [{ OID: '1.3.6.1.4.1.11129.2.4.3', value: 'critical,ASN1:NULL' }],
            },
            ...dates(90),
        }),
    },
};

/** The parameters slotlib.signCSR passes node-openssl-cert2, for the same token and request. */
function signParams(token, csr, options) {
    const mup = common.moduleURIParam(token.module);
    return {
        csr,
        // slotlib sets the hash from the key's allowed mechanisms (sha256 here) and adds the module
        options: { ...options, hash: 'sha256', module: token.module },
        ca: token.ca,
        pkcs11: {
            uri: openssl2.common.encodePKCS11URI({ serial: token.serial, [mup.param]: mup.prefix + token.objectid, type: 'private' }),
            pin: token.pin,
            modulePath: token.module,
        },
    };
}

/** slotlib.signCSR with NATIVESIGNING set to `native`, and what the agent logged about native signing. */
async function slotlibSignCSR(token, csr, options, native) {
    config.NATIVESIGNING = native;
    const logged = [];
    const log = console.log;
    console.log = (...args) => {
        if (String(args[0]).startsWith('Native signing')) logged.push(args.join(' '));
        log(...args);
    };
    try {
        const cert = await signCSR({
            publiccert: token.ca, csr, options, module: token.module,
            serial: token.serial, pin: token.pin, objectid: token.objectid,
        });
        return { cert, logged };
    } finally {
        console.log = log;
        config.NATIVESIGNING = false;
    }
}

function suite(name, token, caseNames) {
    test.describe(name, { skip: token ? false : 'LIVE_* variables not set' }, () => {
        for (const caseName of caseNames) {
            test(caseName, async () => {
                const c = cases[caseName];
                const csr = await newCSR(c.subject);
                const options = c.options();
                // the agent's path as before: slotlib.signCSR with OpenSSL
                const reference = await slotlibSignCSR(token, csr, structuredClone(options), false);
                assert.deepEqual(reference.logged, []);
                // the same with NATIVESIGNING on
                const candidate = await slotlibSignCSR(token, csr, structuredClone(options), '1');
                assert.deepEqual(candidate.logged, [], 'native signing fell back to OpenSSL');

                const ca = new X509Certificate(token.ca);
                assert.ok(new X509Certificate(candidate.cert).verify(ca.publicKey), 'native signature verifies with the CA');
                // node-pki-signer rebuilds the OpenSSL certificate's TBS byte for byte from the same parameters
                const rebuilt = await shadowCASignCSR(signParams(token, csr, structuredClone(options)), reference.cert);
                assert.equal(rebuilt.signature, 'valid', 'OpenSSL certificate verifies with the CA');
                assert.equal(rebuilt.outcome, 'match', JSON.stringify(rebuilt.fields ?? rebuilt.detail));
                // and the native certificate is that TBS with its own serial number
                const own = await shadowCASignCSR(signParams(token, csr, structuredClone(options)), candidate.cert);
                assert.equal(own.signature, 'valid', 'native certificate verifies with the CA');
                assert.equal(own.outcome, 'match', JSON.stringify(own.fields ?? own.detail));
            });
        }
    });
}

const env = process.env;
const pkcs11 = env.LIVE_PKCS11_MODULE && env.LIVE_PKCS11_SERIAL && env.LIVE_PKCS11_OBJECTID && env.LIVE_PKCS11_CA && env.LIVE_PKCS11_PIN
    ? {
        module: env.LIVE_PKCS11_MODULE, serial: env.LIVE_PKCS11_SERIAL, objectid: env.LIVE_PKCS11_OBJECTID,
        ca: fs.readFileSync(env.LIVE_PKCS11_CA, 'utf8'), pin: env.LIVE_PKCS11_PIN,
    }
    : false;
const kms = env.LIVE_KMS_OBJECTID && env.LIVE_KMS_CA
    ? {
        module: KMS_MODULE, serial: env.LIVE_KMS_SERIAL || '0000000000000000', objectid: env.LIVE_KMS_OBJECTID,
        ca: fs.readFileSync(env.LIVE_KMS_CA, 'utf8'), pin: 'unused',
    }
    : false;

suite('PKCS#11 token', pkcs11, Object.keys(cases));
// two cases keep the KMS cost at four asymmetricSign calls per run
suite('Google Cloud KMS', kms, ['web server (the SCEP e2e template)', 'OCSP service certificate']);

test.after(() => fs.rmSync(process.env.STATEDIR, { recursive: true, force: true }));
