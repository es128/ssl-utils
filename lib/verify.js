/* jshint node: true */
'use strict';

var spawn = require('child_process').spawn;

exports. checkCertificateExpiration =
function checkCertificateExpiration (cert, cb) {
	var openssl = spawn('openssl', ['x509', '-noout', '-enddate']);
	openssl.stdout.on('data', function (out) {
		var data = out.toString().trim();
		var certExpiry, err;
		try {
			certExpiry = new Date(data.split('=')[1]);
		} catch (_er) {
			err = _er;
		}
		cb(err, certExpiry);
	});
	openssl.stdin.write(cert);
	openssl.stdin.end();
};

var      verifyCertificate =
exports. verifyCertificate =
function verifyCertificate (cert, options, cb) {
	var cliArgs = ['verify'];
	var err;
	if (!options) {
		options = {};
	} else if (typeof options === 'function') {
		cb = options;
		options = {};
	} else if (options.CAfile) {
		cliArgs.push('-CAfile', options.CAfile);
	}
	var openssl = spawn('openssl', cliArgs);
	openssl.stdout.on('data', function (out) {
		var certStatus = {};
		var data = certStatus.output = out.toString().trim();
		var validRe = /OK$|unable to get (local )?issuer certificate[\r\n]/;
		certStatus.valid = validRe.test(data);
		certStatus.verifiedCA = certStatus.valid && !/error/.test(data);
		certStatus.selfSigned = /self signed certificate[\r\n]/.test(data);
		if (/unable to load certificate[\r\n]/.test(data)) {
			err = new Error('Invalid certificate');
		}
		cb(err, certStatus);
	});
	openssl.stdin.write(cert);
	openssl.stdin.end();
};

var      verifyKey =
exports. verifyKey =
function verifyKey (key, cb) {
	var err;
	var openssl = spawn('openssl', ['rsa', '-noout', '-check']);
	openssl.stdout.on('data', function (out) {
		var keyStatus = {valid: true};
		var data = keyStatus.output = out.toString().trim();
		if (/unable to load Private Key[\r\n]/.test(data)) {
			keyStatus.valid = false;
			err = new Error('Invalid key');
		}
		cb(err, keyStatus);
	});
	openssl.stdin.write(key);
	openssl.stdin.end();
};

var      compareModuli =
exports. compareModuli =
function compareModuli (cert, key, cb) {
	var fromCert = spawn('openssl', ['x509', '-noout', '-modulus']);
	fromCert.stdout.on('data', function (outC) {
		var certModulus = outC.toString().trim();
		var fromKey = spawn('openssl', ['rsa', '-noout', '-modulus']);
		fromKey.stdout.on('data', function (outK) {
			var keyModulus = outK.toString().trim();
			var result = {
				match: certModulus === keyModulus,
				certModulus: certModulus.split('=')[1],
				keyModulus: keyModulus.split('=')[1]
			};
			cb(null, result);
		});
		fromKey.stdin.write(key);
		fromKey.stdin.end();
	});
	fromCert.stdin.write(cert);
	fromCert.stdin.end();
};

exports. verifyCertificateKey =
function verifyCertificateKey (cert, key, options, cb) {
	var result = {};
	if (typeof options === 'function') {
		cb = options;
		options = {};
	}
	verifyCertificate(cert, options, function (err, certStatus) {
		result.certStatus = certStatus;
		if (err) {return cb(err, result);}
		verifyKey(key, function (err, keyStatus) {
			result.keyStatus = keyStatus;
			if (err) {return cb(err, result);}
			compareModuli(cert, key, function (err, moduliResult) {
				result.match = moduliResult.match;
				cb(err, result);
			});
		});
	});
};
