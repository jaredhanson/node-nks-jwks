/**
 * Module dependencies.
 */
var uri = require('url')
  , request = require('request')
  , Factory = require('./factory')
  , RSAKey = require('./keys/rsa')
  , debug = require('debug')('nks-jwks');


/**
 * Finds a key in a JSON Web Key Set.
 *
 * This finder finds keys or certificates in a JSON Web Key Set (JWK Set).  By
 * default, it selects keys used for signing and supports finding a specific key
 * by ID, which is useful during key rollover.
 *
 * In order for this finder to operate, the entity musth have a `jwksUrl`
 * property.  It is assumed that the value of this property has been verified as
 * belonging to the entity in question.  How this is accomplished is out of
 * scope of this package, but it is an important security consideration for the
 * application to ensure.  See the "Related Packages" section below for packages
 * that can assist in this process.
 *
 * References:
 *  - [JSON Web Key (JWK)](http://tools.ietf.org/html/draft-ietf-jose-json-web-key-20)
 *
 * Related Packages:
 *  - [nds-openidconfiguration](https://github.com/jaredhanson/node-nds-openidconfiguration)
 *
 * @param {Object} options
 * @return {Function}
 * @api public
 */
module.exports = function(options) {
  options = options || {};
  var use = options.use || 'sig';
  if (use == 'signature') { use = 'sig'; }
  if (use == 'encryption') { use = 'enc'; }
  var secure = options.secure;

  var factory = new Factory();
  factory.use(RSAKey);
  
  return function jwks(entity, options, cb) {
    var url = entity.jwksUrl;
    
    // This entity does not have a JWK Set.  Invoke callback without an error or
    // key.  If additional mechanisms are supported, attempts to find the key
    // will continue.
    if (!url) { return cb(); }
    
    var purl = uri.parse(url);
    if (!(purl.protocol == 'https:' || (purl.protocol == 'http:' && secure === false))) { return cb(); }
    
    request({
      url: url,
      headers: {
        'Accept': 'application/json'
      }
    }, function(err, res, body) {
      if (err) { return cb(err); }
      if (res.statusCode != 200) {
        return cb(new Error('Unexpected status ' + res.statusCode + ' from ' + url));
      }
      
      var json;
      try {
        json = JSON.parse(body);
      } catch (ex) {
        return cb(new Error('Failed to parse JWK Set from ' + url));
      }
      
      var jwks = json.keys || []
        , jwk, i, len
        , keys = [], key, skey;
      for (i = 0, len = jwks.length; i < len; i++) {
        jwk = jwks[i];
        
        if (jwk.use && jwk.use != use) { continue; }
        if (jwk.alg && jwk.alg != options.alg) { continue; }
        
        key = factory.create(jwk);
        if (!key) { continue; }
        if (key.supports(options.alg)) {
          keys.push(key);
        }
      }
      
      
      skey = keys[0];
      for (i = 0, len = keys.length; i < len; i++) {
        key = keys[i];
        if (key.id && key.id == options.kid) {
          skey = key;
          break;
        }
      }
      
      if (!skey) {
        // TODO: Better error message
        return cb(new Error('No suitable key'));
      }
      
      
      // TODO: Implement support for fetching x5u URLs
      
      return cb(null, skey.toPEM());
    });
    
  }
};
