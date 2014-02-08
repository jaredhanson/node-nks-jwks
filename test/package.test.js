/* global describe, it, expect */

var jwks = require('..');

describe('nks-jwks', function() {
  
  it('should export function', function() {
    expect(jwks).to.be.a('function');
  });
  
});
