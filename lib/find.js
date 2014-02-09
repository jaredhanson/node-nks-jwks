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
 * References:
 *  - [JSON Web Key (JWK)](http://tools.ietf.org/html/draft-ietf-jose-json-web-key-20)
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

  var factory = new Factory();
  factory.use(RSAKey);
  
  return function jwks(entity, options, cb) {
    // TODO: support entity as string or object
    
    var url = entity.jwksUrl;
    
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
      
      
      return cb(null, skey.toPEM());
    });
    
  }
};
