/**
 * Module dependencies.
 */
var base64url = require('base64url')
  , forge = require('node-forge')
  , pki = forge.pki
  , BigInteger = forge.jsbn.BigInteger;


/**
 * Constructs an RSA key.
 *
 * References:
 *  - [JSON Web Key (JWK)](http://tools.ietf.org/html/draft-ietf-jose-json-web-key-20)
 *  - [JSON Web Algorithms (JWA)](http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-20)
 *
 * @api public
 */
function RSAKey(jwk) {
  this.id = jwk.kid;
  this._jwk = jwk;
}

/**
 * Key type.
 */
RSAKey.prototype.type = 'RSA';

/**
 * Test if key supports algorithm.
 *
 * @param {String} alg
 * @return {Boolean}
 * @api public
 */
RSAKey.prototype.supports = function(alg) {
  if (!alg) { return false; }
  var match = alg.match(/RS(256|384|512)/)
  return !!match;
}

/**
 * Convert key to PEM-encoded key.
 *
 * @return {String}
 * @api public
 */
RSAKey.prototype.toPEM = function() {
  var n = base64url.decode(this._jwk.n, 'hex')
    , e = base64url.decode(this._jwk.e, 'hex');
  
  var key = pki.setRsaPublicKey(new BigInteger(n, 16), new BigInteger(e, 16));
  return pki.publicKeyToPem(key);
}


/**
 * Expose `RSAKey`.
 */
module.exports = RSAKey;
