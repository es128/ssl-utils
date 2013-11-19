ssl-utils
=========

A handful of wrappers around [OpenSSL](http://www.openssl.org/) commands for Node.js

Usage
-----
Install with npm: `npm install ssl-utils --save`

```js
var ssl = require('ssl-utils');

//// generate a new SSL certificate and key ////
var csr = {
  subject: {
    C:  'US',
    ST: 'FL',
    L:  'Hollywood',
    O:  'es128',
    OU: 'me',
    CN: 'www.domain.name'
  }
  // subjectaltname could also be added
};

ssl.generateCertBuffer(
  'myCert', /*temp filename prefix*/
  false, /*whether to keep temp files*/
  csr, /*cert info, see above*/
  caKeyPath,  /*path to CA signer's key*/
  caCertPath, /*path to CA signer's cert*/
  function (err, key, cert, fingerprint, hash) { /*callback*/}
);


//// check the validity of a cert/key pair ////
var cert = certContents; //String or Buffer

ssl.checkCertificateExpiration(cert, function (expiry) {
    //expiry is a Date instance
    var remainingTime = expiry.getTime() - Date.now();
});
```


API
---
#### generateCertBuffer(prefix, keepTmp, certInfo, caKeyPath, caCertPath, callback)
Generates a new ssl certificate and private key, signed by the provided certificate authority.

* __prefix__: `String` prefix to use when naming temp files
* __keepTmp__: `Boolean` whether temp files should be automatically deleted
* __certInfo__: `Object` identity info to embed in the certificate
  * _subject_: required child object with `C` (Country), `ST` (State), `L` (Locality),
    `O` (Organization), `OU` (Organizational Unit), `CN` (Common Name)
  * _subjectaltname_: optional string, comma-separated list of alt names for the certificate such
    as `DNS:foo.domain.name, DNS:bar.domain.name, DNS:localhost, IP:127.0.0.1`
* __caKeyPath__:  `String` path to the certificate authority's private key pem file
* __caCertPath__: `String` path to the certificate authority's certificate pem file
* __callback__: `Function` in the form of `callback(err, keyBuffer, certBuffer)`

#### generateCert
Same as `generateCertBuffer` except it returns file paths to the temp files for the key and cert
instead of buffers.

##### _Additional certificate generation methods_
`createKeypair`, `createCertRequestConfig`, `createExtensionsFile`, `createCertRequest`, and
`createCert` are used by the above methods in the generation process, but are also exported and
can be used directly. Check the
[`generate.js`](https://github.com/es128/ssl-utils/blob/master/lib/generate.js) source code for
the method signatures.

#### checkCertificateExpiration(cert, callback)
Parses a provided certificate's expiration date.

* __cert__: `String|Buffer` contents of the certificate pem file
* __callback__: `Function` in the form of `callback(err, certExpiry)` where certExpiry is a `Date`
  instance.

#### verifyCertificateKey(cert, key, [options], callback)
Checks the validity of a provided certificate and private key, as well as whether they match.

* __cert__: `String|Buffer` contents of the certificate
* __key__:  `String|Buffer` contents of the private key
* __options__: `Object` to verify the certificate against a specific certificate authority, pass
  the path the CA file in `options.CAfile`
* __callback__: `Function` in the form of `callback(err, result)` where `result` is an object
  containing `certStatus`, `keyStatus`, and `match`
  * _result.certStatus_: `Object` containing `Boolean` properties  `valid`, `verifiedCA`, and
    `selfSigned` as well as `output` containing the raw output from OpenSSL
  * _result.keyStatus_:  `Object` containing `valid` and `output`
  * _result.match_: `Boolean` whether the cert's and key's modulus values match

##### _Additional certificate generation methods_
`verifyCertificate`, `verifyKey`, `compareModuli` are used by `verifyCertificateKey`, but are also
exported and can be used directly. Check the
[`verify.js`](https://github.com/es128/ssl-utils/blob/master/lib/verify.js) source code for
the method signatures.


Acknowledgements
----------------
The certificate generation code was derived from [certgen](https://github.com/bcle/certgen).


License
-------
[MIT](https://raw.github.com/es128/ssl-utils/master/LICENSE)
