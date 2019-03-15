'use strict';

var keyfetch = require('./keyfetch.js');
var testIss = "https://example.auth0.com";

keyfetch.init({});
keyfetch.oidcJwks(testIss).then(function (hits) {
  keyfetch._clear();
  //console.log(hits);
  return keyfetch.oidcJwk(hits[0].thumbprint, testIss).then(function () {
    return keyfetch.oidcJwk(hits[0].thumbprint, testIss).then(function (/*jwk*/) {
      //console.log(jwk);
    });
  });
}).then(function () {
  console.log("Fetching PASSES");
}).catch(function (err) {
  console.error("NONE SHALL PASS!");
  console.error(err);
  process.exit(1);
});

/*global Promise*/
var keypairs = require('keypairs.js');
keypairs.generate().then(function (pair) {
  return keypairs.signJwt({
    jwk: pair.private, iss: 'https://example.com/', sub: 'mikey', exp: '1h'
  }).then(function (jwt) {
    return Promise.all([
      keyfetch.jwt.verify(jwt, { jwk: pair.public }).then(function (verified) {
        if (!(verified.claims && verified.claims.exp)) {
          throw new Error("malformed decoded token");
        }
      })
    , keyfetch.jwt.verify(keyfetch.jwt.decode(jwt), { jwk: pair.public }).then(function (verified) {
        if (!(verified.claims && verified.claims.exp)) {
          throw new Error("malformed decoded token");
        }
      })
    , keyfetch.jwt.verify(jwt, { jwks: [pair.public] })
    , keyfetch.jwt.verify(jwt, { jwk: pair.public, issuers: ['https://example.com/'] })
    , keyfetch.jwt.verify(jwt, { jwk: pair.public, issuers: ['https://example.com'] })
    , keyfetch.jwt.verify(jwt, { jwk: pair.public, issuers: ['*'] })
    , keyfetch.jwt.verify(jwt, { jwk: pair.public, issuers: ['http://example.com'] })
        .then(e("bad scheme")).catch(throwIfNotExpected)
    , keyfetch.jwt.verify(jwt, { jwk: pair.public, issuers: ['https://www.example.com'] })
        .then(e("bad prefix")).catch(throwIfNotExpected)
    , keyfetch.jwt.verify(jwt, { jwk: pair.public, issuers: ['https://wexample.com'] })
        .then(e("bad sld")).catch(throwIfNotExpected)
    , keyfetch.jwt.verify(jwt, { jwk: pair.public, issuers: ['https://example.comm'] })
        .then(e("bad tld")).catch(throwIfNotExpected)
    , keyfetch.jwt.verify(jwt, { jwk: pair.public, claims: { iss: 'https://example.com/' } })
    , keyfetch.jwt.verify(jwt, { jwk: pair.public, claims: { iss: 'https://example.com' } })
        .then(e("inexact claim")).catch(throwIfNotExpected)
    ]).then(function () {
      console.log("JWT PASSES");
    }).catch(function (err) {
      console.error("NONE SHALL PASS!");
      console.error(err);
      process.exit(1);
    });
  });
});
/*
var jwt = '...';
keyfetch.verify({ jwt: jwt }).catch(function (err) {
  console.log(err);
});
*/

function e(msg) {
  return new Error("ETEST: " + msg);
}
function throwIfNotExpected(err) {
  if ("ETEST" === err.message.slice(0, 5)) { throw err; }
}
