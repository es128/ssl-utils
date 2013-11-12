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
			certExpiry = new Date(data.slice(1 + data.indexOf('=')));
		} catch (_er) {
			err = _er;
		}
		cb(err, certExpiry);
	});
	openssl.stdin.write(cert);
};

exports. verifyCertificate =
function verifyCertificate (cert, options, cb) {
	var cliArgs = [];
	var certStatus = {};
	var err;
	if (typeof options === 'function') {
		cb = options;
		options = {};
	} else if (options.CAfile) {
		cliArgs.push('-CAfile', options.CAfile);
	}
	var openssl = spawn('openssl', cliArgs);
	openssl.stdout.on('data', function (out) {
		var validRe = /OK$|unable to get (local )?issuer certificate[\r\n]/;
		certStatus.valid = validRe.test(out);
		certStatus.CAverified = certStatus.valid && !/error/.test(out);
		certStatus.selfSigned = /self signed certificate[\r\n]/.test(out);
		if (/unable to load certificate[\r\n]/.test(out)) {
			err = new Error('Invalid certificate');
		}
		cb(err, certStatus);
	});
	openssl.stdin.write(cert);
};

exports. verifyKey =
function verifyKey (key, cb) {
	var err;
	var openssl = spawn('openssl', ['rsa', '-noout', '-check']);
	openssl.stdout.on('data', function (out) {
		if (/unable to load Private Key[\r\n]/.test(out)) {
			err = new Error('Invalid key');
		}
		cb(err, out);
	});
	openssl.stdin.write(key);
};
