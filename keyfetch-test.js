'use strict';

var keyfetch = require('./keyfetch.js');
var testUrl = "https://example.auth0.com";

keyfetch.init({});
keyfetch.oidcJwks().then(function (jwks) {
  keyfetch._clear();
  console.log(jwks);
  return keyfetch.oidcJwk(jwks[0].thumbprint, "https://example.auth0.com").then(function () {
    return keyfetch.oidcJwk(jwks[0].thumbprint, "https://example.auth0.com").then(function (jwk) {
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
