/* global describe, it, expect */

var path = require('path')
  , fs = require('fs')
  , find = require('../lib/find')
  , MODULE_PATH = path.resolve(__dirname, '../lib/find');


describe('find', function() {
  
  it('should export a setup function', function() {
    expect(find).to.be.a('function');
  });
  
  describe('finding RSA key with alg option', function() {
    // ** MOCKS **
    var request = function(options, cb) {
      expect(options.url).to.equal('https://www.example.com/jwks.json');
      expect(options.headers['Accept']).to.equal('application/json');
        
      process.nextTick(function() {
        // http://tools.ietf.org/html/draft-ietf-jose-json-web-key-20#appendix-A.1
        var keys = fs.readFileSync(path.resolve(__dirname, 'data/example-public-keys.json'), 'utf8');
        return cb(null, { statusCode: 200 }, keys);
      });
    };
    
    
    var setup = $require(MODULE_PATH, { request: request });
    var find = setup();
    var key;
    
    before(function(done) {
      var entity = { 
        id: 'https://www.example.com/',
        issuer: 'https://www.example.com/',
        jwksUrl: 'https://www.example.com/jwks.json'
      };
      
      find(entity, { alg: 'RS256' }, function(err, k) {
        if (err) { return done(err); }
        key = k;
        done();
      });
    });
    
    it('should find key', function() {
      var ekey = [
          '-----BEGIN PUBLIC KEY-----'
        , 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0vx7agoebGcQSuuPiLJX'
        , 'ZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tS'
        , 'oc/BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ/2W+5JsGY4Hc5n9yBXArwl93lqt'
        , '7/RN5w6Cf0h4QyQ5v+65YGjQR0/FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0'
        , 'zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt+bFTWhAI4vMQFh6WeZu0f'
        , 'M4lFd2NcRwr3XPksINHaQ+G/xBniIqbw0Ls1jF44+csFCur+kEgU8awapJzKnqDK'
        , 'gwIDAQAB'
        , '-----END PUBLIC KEY-----'
        , ''
      ].join('\r\n');
      
      expect(key).to.equal(ekey);
    });
  });
  
  describe('handling unexpected status', function() {
    // ** MOCKS **
    var request = function(options, cb) {
      expect(options.url).to.equal('https://www.example.com/jwks.json');
        
      process.nextTick(function() {
        return cb(null, { statusCode: 404 }, 'Cannot GET /jwks.json');
      });
    };
    
    
    var setup = $require(MODULE_PATH, { request: request });
    var find = setup();
    var key, error;
    
    before(function(done) {
      var entity = { 
        id: 'https://www.example.com/',
        issuer: 'https://www.example.com/',
        jwksUrl: 'https://www.example.com/jwks.json'
      };
      
      find(entity, { alg: 'RS256' }, function(err, k) {
        error = err;
        key = k;
        done();
      });
    });
    
    it('should error', function() {
      expect(error).to.be.an.instanceOf(Error);
      expect(error.message).to.equal('Unexpected status 404 from https://www.example.com/jwks.json');
      expect(error.status).to.be.undefined;
    });
    
    it('should not find key', function() {
      expect(key).to.be.undefined;
    });
  });
  
  describe('handling unparsable body', function() {
    // ** MOCKS **
    var request = function(options, cb) {
      expect(options.url).to.equal('https://www.example.com/jwks.json');
        
      process.nextTick(function() {
        return cb(null, { statusCode: 200 }, '<xml></xml>');
      });
    };
    
    
    var setup = $require(MODULE_PATH, { request: request });
    var find = setup();
    var key, error;
    
    before(function(done) {
      var entity = { 
        id: 'https://www.example.com/',
        issuer: 'https://www.example.com/',
        jwksUrl: 'https://www.example.com/jwks.json'
      };
      
      find(entity, { alg: 'RS256' }, function(err, k) {
        error = err;
        key = k;
        done();
      });
    });
    
    it('should error', function() {
      expect(error).to.be.an.instanceOf(Error);
      expect(error.message).to.equal('Failed to parse JWK Set from https://www.example.com/jwks.json');
      expect(error.status).to.be.undefined;
    });
    
    it('should not find key', function() {
      expect(key).to.be.undefined;
    });
  });
  
  describe('attempting to find key from an entity that does not support JWK Set', function() {
    // ** MOCKS **
    var request = function(options, cb) {
      throw new Error('should not be called');
    };
    
    
    var setup = $require(MODULE_PATH, { request: request });
    var find = setup();
    var key, error;
    
    before(function(done) {
      var entity = { 
        id: 'https://www.example.com/',
        issuer: 'https://www.example.com/'
      };
      
      find(entity, { alg: 'RS256' }, function(err, k) {
        if (err) { return done(err); }
        key = k;
        done();
      });
    });
    
    it('should pass without error or key', function() {
      expect(key).to.be.undefined;
    });
  });
  
  describe('attempting to find key from an entity whose keys cannot be fetched securely', function() {
    // ** MOCKS **
    var request = function(options, cb) {
      throw new Error('should not be called');
    };
    
    
    var setup = $require(MODULE_PATH, { request: request });
    var find = setup();
    var key, error;
    
    before(function(done) {
      var entity = { 
        id: 'https://www.example.com/',
        issuer: 'https://www.example.com/',
        jwksUrl: 'http://www.example.com/jwks.json'
      };
      
      find(entity, { alg: 'RS256' }, function(err, k) {
        if (err) { return done(err); }
        key = k;
        done();
      });
    });
    
    it('should pass without error or key', function() {
      expect(key).to.be.undefined;
    });
  });
  
  describe('attempting to find key from an entity whose keys cannot be fetched with a supported protocol', function() {
    // ** MOCKS **
    var request = function(options, cb) {
      throw new Error('should not be called');
    };
    
    
    var setup = $require(MODULE_PATH, { request: request });
    var find = setup();
    var key, error;
    
    before(function(done) {
      var entity = { 
        id: 'https://www.example.com/',
        issuer: 'https://www.example.com/',
        jwksUrl: 'ftp://www.example.com/jwks.json'
      };
      
      find(entity, { alg: 'RS256' }, function(err, k) {
        if (err) { return done(err); }
        key = k;
        done();
      });
    });
    
    it('should pass without error or key', function() {
      expect(key).to.be.undefined;
    });
  });
  
  describe('attempting to find key from an entity whose keys cannot be fetched securely, but secure fetching disabled', function() {
    // ** MOCKS **
    var request = function(options, cb) {
      expect(options.url).to.equal('http://www.example.com/jwks.json');
      expect(options.headers['Accept']).to.equal('application/json');
        
      process.nextTick(function() {
        // http://tools.ietf.org/html/draft-ietf-jose-json-web-key-20#appendix-A.1
        var keys = fs.readFileSync(path.resolve(__dirname, 'data/example-public-keys.json'), 'utf8');
        return cb(null, { statusCode: 200 }, keys);
      });
    };
    
    
    var setup = $require(MODULE_PATH, { request: request });
    var find = setup({ secure: false });
    var key, error;
    
    before(function(done) {
      var entity = { 
        id: 'https://www.example.com/',
        issuer: 'https://www.example.com/',
        jwksUrl: 'http://www.example.com/jwks.json'
      };
      
      find(entity, { alg: 'RS256' }, function(err, k) {
        if (err) { return done(err); }
        key = k;
        done();
      });
    });
    
    it('should find key', function() {
      var ekey = [
          '-----BEGIN PUBLIC KEY-----'
        , 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0vx7agoebGcQSuuPiLJX'
        , 'ZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tS'
        , 'oc/BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ/2W+5JsGY4Hc5n9yBXArwl93lqt'
        , '7/RN5w6Cf0h4QyQ5v+65YGjQR0/FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0'
        , 'zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt+bFTWhAI4vMQFh6WeZu0f'
        , 'M4lFd2NcRwr3XPksINHaQ+G/xBniIqbw0Ls1jF44+csFCur+kEgU8awapJzKnqDK'
        , 'gwIDAQAB'
        , '-----END PUBLIC KEY-----'
        , ''
      ].join('\r\n');
      
      expect(key).to.equal(ekey);
    });
  });
  
});
