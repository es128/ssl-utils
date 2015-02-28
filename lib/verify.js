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
	function handler (out) {
		var certStatus = {};
		var data = certStatus.output = out.toString().trim();
		var validRe = /OK$|unable to get (local )?issuer certificate/;
		certStatus.valid = validRe.test(data);
		certStatus.verifiedCA = certStatus.valid && !/error/.test(data);
		certStatus.selfSigned = /self signed certificate/.test(data);
		if (/unable to load certificate/.test(data)) {
			err = new Error('Invalid certificate');
		}
		cb(err, certStatus);
	}
	openssl.stdout.on('data', handler);
	openssl.stderr.on('data', handler);
	openssl.stdin.write(cert);
	openssl.stdin.end();
};

var      verifyKey =
exports. verifyKey =
function verifyKey (key, options, cb) {
	var err;

	var cliArgs = ['rsa', '-noout', '-check'];

	if (!options) {
		options = {};
	} else if (typeof options === 'function') {
		cb = options;
		options = {};
	} else if (options.pass) {
		cliArgs.push('-passin', "pass:" + options.pass);
	}

	var openssl = spawn('openssl', cliArgs);
	function handler (out) {
		var keyStatus = {valid: true};
		var data = keyStatus.output = out.toString().trim();
		if (/unable to load Private Key/.test(data)) {
			keyStatus.valid = false;
			err = new Error('Invalid key');
		}
		cb(err, keyStatus);
	}
	openssl.stdout.on('data', handler);
	openssl.stderr.on('data', handler);
	openssl.stdin.write(key);
	openssl.stdin.end();
};

var      compareModuli =
exports. compareModuli =
function compareModuli (cert, key, options, cb) {

	if (!options) {
		options = {};
	} else if (typeof options === 'function') {
		cb = options;
		options = {};
	}

	var fromCert = spawn('openssl', ['x509', '-noout', '-modulus']);
	fromCert.stdout.on('data', function (outC) {
		var certModulus = outC.toString().trim();

		var cliArgs = ['rsa', '-noout', '-modulus'];

		if (options.pass) {
			cliArgs.push('-passin', "pass:" + options.pass);
		}

		var fromKey = spawn('openssl', cliArgs);
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
		verifyKey(key, options, function (err, keyStatus) {
			result.keyStatus = keyStatus;
			if (err) {return cb(err, result);}
			compareModuli(cert, key, options, function (err, moduliResult) {
				result.match = moduliResult.match;
				cb(err, result);
			});
		});
	});
};
