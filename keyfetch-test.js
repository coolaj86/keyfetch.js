'use strict';

var keyfetch = require('./keyfetch.js');
var testIss = "https://example.auth0.com";

keyfetch.init({});
keyfetch.oidcJwks(testIss).then(function (hits) {
  keyfetch._clear();
  console.log(hits);
  return keyfetch.oidcJwk(hits[0].thumbprint, testIss).then(function () {
    return keyfetch.oidcJwk(hits[0].thumbprint, testIss).then(function (jwk) {
      console.log(jwk);
    });
  });
}).catch(function (err) {
  console.error(err);
});

/*
var jwt = '...';
keyfetch.verify({ jwt: jwt }).catch(function (err) {
  console.log(err);
});
*/
