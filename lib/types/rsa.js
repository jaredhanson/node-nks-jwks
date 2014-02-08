/**
 * Module dependencies.
 */
var base64url = require('base64url')
  , forge = require('node-forge')
  , pki = forge.pki
  , BigInteger = forge.jsbn.BigInteger;


function RSAKey(jwk) {
  this.id = jwk.kid;
  this._jwk = jwk;
}

RSAKey.prototype.type = 'RSA';

RSAKey.prototype.supports = function(alg) {
  var match = alg.match(/RS(256|384|512)?/i)
  return !!match;
}

RSAKey.prototype.toPEM = function() {
  var n = base64url.decode(this._jwk.n, 'hex')
    , e = base64url.decode(this._jwk.e, 'hex');
  
  var key = pki.setRsaPublicKey(new BigInteger(n, 16), new BigInteger(e, 16));
  return pki.publicKeyToPem(key);
}


module.exports = RSAKey;
