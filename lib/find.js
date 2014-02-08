var uri = require('url')
  , request = require('request')
  , Factory = require('./factory')
  , RSAKey = require('./types/rsa')
  , debug = require('debug')('nks-jwks');


module.exports = function() {
  var factory = new Factory();
  factory.use(RSAKey);
  
  
  return function jwks(entity, options, cb) {
    // TODO: support entity as string or object
    
    var url = entity.jwksUrl
      , algo = options.alg;
    
    // TODO: Set accept header to JSON
    
    var match = algo.match(/(RS|ES)(256|384|512)?/i)
    
    if (!match) {
      return cb(new Error('Unsupported JWT algorithm: ' + algo));
    }
    
    var type = match[1].toUpperCase()
      , bits = match[2];
    
    request(url, function(err, res, body) {
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
        , keys = [], key;
      for (i = 0, len = jwks.length; i < len; i++) {
        jwk = jwks[i];
        
        key = factory.create(jwk);
        console.log('CREATED');
        console.log(key);
        
        if (!key) { continue; }
        
        keys.push(key);
        
        
        // TODO: check "kty" matches alg
        // TODO: check "use" (optional)
        // TODO: check "kid"
        // TODO: build candidates, then select on kid or first, if no kid
        
        // TODO: this is optional
        if (jwk.alg == algo) {
          //skey = jwk;
          //break;
        }
      }
      
      var skey = keys[0];
      
      if (!skey) {
        // TODO: Better error message
        return cb(new Error('No suitable key'));
      }
      
      
      return cb(null, skey.toPEM());
    });
    
  }
};
