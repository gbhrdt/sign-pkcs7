var pkcs7 = require('bindings')('pkcs7');

var PKCS7_CONTENT_REGEX = /Content-Disposition:[^\n]+\s*?([A-Za-z0-9+=/\r\n]+)\s*?-----/;

var sign = function(manifestContent, certData, pKeyData, intermediate) {
  var pkcs7sig = pkcs7.sign(certData, pKeyData, manifestContent, intermediate),
    content = PKCS7_CONTENT_REGEX.exec(pkcs7sig.toString());
  return Buffer.from(content[1], 'base64');
};

var verify = function(file, signature, cert, intermediate, rootCA) {
  if (typeof cert === 'string') {
    cert = Buffer.from(cert);
  }
  if (typeof intermediate === 'string') {
    intermediate = Buffer.from(intermediate);
  }
  if (typeof rootCA === 'string') {
    rootCA = Buffer.from(rootCA);
  }
  var result = pkcs7.verify(file, signature, cert, intermediate, rootCA);
  if (result !== 1) {  // 1 == successful verification
    throw new Error('Invalid signature');
  }
  return true;
};

module.exports = {
  sign: sign,
  verify: verify
};
