function Factory() {
  this._types = {};
}

Factory.prototype.use = function(type, ctor) {
  if (!ctor) {
    ctor = type;
    type = ctor.prototype.type;
  }
  this._types[type] = ctor;
  return this;
};

Factory.prototype.create = function(jwk) {
  var ctor = this._types[jwk.kty];
  if (!ctor) { return null; }
  return new ctor(jwk);
}


module.exports = Factory;
