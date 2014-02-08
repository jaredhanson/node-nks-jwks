var uri = require('url')
  , request = require('request')
  , Factory = require('./factory')
  , RSAKey = require('./types/rsa')
  , debug = require('debug')('nks-jwks');


module.exports = function(options) {
  options = options || {};
  var use = options.use || 'sig';
  if (use == 'signature') { use = 'sig'; }

  var factory = new Factory();
  factory.use(RSAKey);
  
  return function jwks(entity, options, cb) {
    // TODO: support entity as string or object
    
    var url = entity.jwksUrl
      , algo = options.alg;
    
    var match = algo.match(/(RS|ES)(256|384|512)?/i)
    
    if (!match) {
      return cb(new Error('Unsupported JWT algorithm: ' + algo));
    }
    
    var type = match[1].toUpperCase()
      , bits = match[2];
    
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
      
      //console.log(json)
      
      var jwks = json.keys || []
        , jwk, i, len
        , keys = [], key, skey;
      for (i = 0, len = jwks.length; i < len; i++) {
        jwk = jwks[i];
        
        if (jwk.use && jwk.use != use) { continue; }
        if (jwk.alg && jwk.alg != options.alg) { continue; }
        
        key = factory.create(jwk);
        if (!key) { continue; }
        
        // TODO: check if key can handle alg
        keys.push(key);
      }
      
      
      for (i = 0, len = keys.length; i < len; i++) {
        key = keys[i];
        if (key.id && key.id == options.kid) {
          skey = key;
          break;
        }
      }
      
      skey = skey || keys[0];
      
      if (!skey) {
        // TODO: Better error message
        return cb(new Error('No suitable key'));
      }
      
      
      return cb(null, skey.toPEM());
    });
    
  }
};
