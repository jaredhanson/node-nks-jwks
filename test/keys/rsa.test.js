/* global describe, it, expect */

var RSAKey = require('../../lib/keys/rsa');


describe('RSAKey', function() {
  
  it('should export a constructor', function() {
    expect(RSAKey).to.be.a('function');
  });
  
  it('should be of RSA types', function() {
    expect(RSAKey.prototype.type).to.equal('RSA');
  });
  
  describe('#supports', function() {
    var key = new RSAKey({});
    
    it('should support RS256 algorithm', function() {
      expect(key.supports('RS256')).to.be.true;
    });
    
    it('should support RS384 algorithm', function() {
      expect(key.supports('RS384')).to.be.true;
    });
    
    it('should support RS512 algorithm', function() {
      expect(key.supports('RS512')).to.be.true;
    });
    
    it('should not support RSX256 algorithm', function() {
      expect(key.supports('RSX256')).to.be.false;
    });
    
    it('should return false when passed no argument', function() {
      expect(key.supports()).to.be.false;
    });
    
    it('should return false when passed undefined as argument', function() {
      expect(key.supports(undefined)).to.be.false;
    });
  });
  
});
  