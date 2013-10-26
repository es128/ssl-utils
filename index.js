'use strict';

var tmp = require('tmp');
var fs = require('fs');
var child = require('child_process');

function create_extensions_file(opts, info, cb) {
  var s = '[v3_ca]\n';
  if (info.subjectaltname) {
    s = s + 'subjectAltName = ' + info.subjectaltname + '\n';
  }
  tmp.file(opts, function tmpFileCb(err, path) {
    if (err) return cb(err);
    fs.writeFile(path, s, function writeFileCb(err) {
      cb(err, path);
    });
  });
}


/*
 * Create a certificate request configuration file.
 * opts: file creation options. 'prefix' sets file prefix.
 *       'keep' instructs whether to keep the file upon process exit.
 * info: Object containing a required 'subject' property containing subject's
 *       distinguished name information, and an optional 'subjectaltname' string property
 *       listing the alternate subject names, if any.
 * cb: a callback of the form cb(err, path), where path is the path
 *     of the certificate request file, if successful.
 */
exports.create_cert_request_config = function (opts, info, cb) {
  var hash = info.subject;
  var s = "[ req ]\ndefault_bits           = 2048\n" +
    "default_keyfile        = keyfile.pem\n" +
    "distinguished_name     = req_distinguished_name\n" +
    "prompt                 = no\n\n" +
    "[ req_distinguished_name ]\n";

  var allowableKeys = { C:1, ST:1, L:1, O:1, OU:1, CN:1 };
  Object.keys(hash).forEach(function (key) {
    if (key in allowableKeys) {
      var val = hash[key];
      if (Array.isArray(val))
        val = val[0]; // hack to handle OUs that are arrays of strings
      s = s + key + " = " + val + "\n";
    }
  });

  tmp.file(opts, function tmpFileCb(err, path) {
    if (err) return cb(err);
    fs.writeFile(path, s, function writeFileCb(err) {
      cb(err, path);
    });
  });
}

/*
 * Create a keypair.
 * opts: file creation options. 'prefix' sets file prefix.
 *       'keep' instructs whether to keep the file upon process exit.
 * cb: a callback of the form cb(err, path), where path is the path
 *     of the created file, if successful.
 */
exports.create_keypair = function (opts, cb) {
  tmp.file(opts, function tmpFileCb(err, path) {
    if (err) return cb(err);
    child.exec('openssl genrsa -out ' + path + ' 2048', function execCb(err) {
      cb(err, path);
    });
  });
}

/*
 * Create a certification request.
 * opts: file creation options. 'prefix' sets file prefix.
 *       'keep' instructs whether to keep the file upon process exit.
 * keyPath: the file containing the subject's public key
 * cfgPath: the request configuration file
 * cb: a callback of the form cb(err, path), where path is the path
 *     of the created file, if successful.
 */
exports.create_cert_request = function (opts, keyPath, cfgPath, cb) {
  tmp.file(opts, function tmpFileCb(err, path) {
    if (err) return cb(err);
    child.exec('openssl req -new -key ' + keyPath + ' -config ' + cfgPath + ' -out ' + path,
               function execCb(err) {
      cb(err, path);
    });
  });
}

/*
 * Create a signed certificate from request file.
 * opts: file creation options. 'prefix' sets file prefix.
 *       'keep' instructs whether to keep the file upon process exit.
 * reqPath: the certification request file
 * caKeyPath: the signer's key
 * caCertPath: the signer's certificate
 * cb: a callback of the form cb(err, path), where path is the path
 *     of the created file, if successful.
 */
exports.create_cert = function (opts, reqPath, caKeyPath, caCertPath, extPath, cb) {
  tmp.file(opts, function tmpFileCb(err, path) {
    if (err) return cb(err);
    child.exec('openssl x509 -req -in ' + reqPath + ' -CAkey ' + caKeyPath + ' -CA ' +
                caCertPath + ' -out ' + path + ' -CAcreateserial' +
                ' -extensions v3_ca -extfile ' + extPath,
                function execCb(err) {
      child.exec('openssl x509 -noout -in ' + path + ' -fingerprint -hash',
                  function statsCb(err, stdout) {
        output = stdout.toString().split(/\n/);
        cb(err, path, output[0], output[1]);
      });
    });
  });
}

/*
 * Generate a signed certificate from supplied information.
 * prefix: Temporary file prefix.
 * keepFiles: Whether to keep generated files upon process exit.
 * info: Object containing a required 'subject' property containing subject's
 *       distinguished name information, and an optional 'subjectaltname' string property
 *       listing the alternate subject names, if any.
 * caKeyPath: the signer's key
 * caCertPath: the signer's certificate
 * cb: a callback of the form cb(err, keyPath, certPath)
 */
exports.generate_cert = function (prefix, keepFiles, info, caKeyPath, caCertPath, cb) {

  var tmpFiles = [];
  var opts = { prefix:prefix + '-', postfix:'.pem'}
  exports.create_keypair(opts, function(err, keyPath) {
    if (err) return cb(err);
    opts.postfix = '.cfg';
    exports.create_cert_request_config(opts, info, function (err, cfgPath) {
      if (err) return cb(err);
      tmpFiles.push(cfgPath);
      opts.postfix = '.ext';
      opts.prefix = prefix + '-';
      create_extensions_file(opts, info, function (err, extPath) {
        if (err) return cb(err);
        tmpFiles.push(extPath);
        opts.postfix = '.pem';
        opts.prefix = prefix + '-csr-';
        exports.create_cert_request(opts, keyPath, cfgPath, function (err, reqPath) {
          if (err) return cb(err);
          tmpFiles.push(reqPath);
          opts.prefix = prefix + '-cert-';
          exports.create_cert(opts, reqPath, caKeyPath, caCertPath, extPath,
                              function (err, certPath, fingerprint, hash) {
            if (!keepFiles)
              tmpFiles.forEach( function(path) { fs.unlink(path); } );
            cb(err, keyPath, certPath, fingerprint, hash);
          });
        });
      });
    });
  });
}

/*
 * Same as generate_cert, except that key and certificate contents are returned
 * as buffers instead of paths.
 *
 * prefix: Temporary file prefix.
 * keepFiles: Whether to keep generated files upon process exit.
 * info: Object containing a required 'subject' property containing subject's
 *       distinguished name information, and an optional 'subjectaltname' string property
 *       listing the alternate subject names, if any.
 * caKeyPath: the signer's key
 * caCertPath: the signer's certificate
 * cb: a callback of the form cb(err, keyBuf, certBuf)
 */
exports.generate_cert_buf = function (prefix, keepFiles, info, caKeyPath, caCertPath, cb) {
  exports.generate_cert(prefix, keepFiles, info, caKeyPath, caCertPath,
                        function (err, keyPath, certPath, fingerprint, hash){
    if (err) return cb(err);
    fs.readFile(certPath, function (err, certBuf) {
      if (err) return cb(err);
      fs.readFile(keyPath, function (err, keyBuf) {
        if (!keepFiles) {
          fs.unlink(certPath);
          fs.unlink(keyPath);
        }
        cb(err, keyBuf, certBuf, fingerprint, hash);
      });
    });
  });
}

