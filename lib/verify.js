/* jshint node: true */
'use strict';

var spawn = require('child_process').spawn;

exports. checkCertificateExpiration =
function checkCertificateExpiration (cert, cb) {
	var openssl = spawn('openssl', ['x509', '-noout', '-enddate']);
	openssl.stdout.on('data', function (out) {
		var data, certExpiry, err;
		try {
			data = out.toString().trim();
			certExpiry = new Date(data.slice(1 + data.indexOf('=')));
		} catch (_er) {
			err = _er;
		}
		cb(err, certExpiry);
	});
	openssl.stdin.write(cert);
};
