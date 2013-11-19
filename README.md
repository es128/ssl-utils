ssl-utils
=========

A handful of wrappers around [OpenSSL](http://www.openssl.org/) commands for Node.js

Usage
-----
Install with npm: `npm install ssl-utils`

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
  csr,
  caKeyPath,  /*path to CA signer's key*/
  caCertPath, /*path to CA signer's cert*/
  function (err, key, cert, fingerprint, hash) { /*callback*/}
);


//// check the validity of a cert/key pair ////
var cert = cert contents; //String or Buffer

ssl.checkCertificateExpiration(cert, function (expiry) {
    //expiry is a Date instance
    var remainingTime = expiry.getTime() - Date.now();
});
```
