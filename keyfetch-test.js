'use strict';

var keyfetch = require('./keyfetch.js');

keyfetch.init({});
keyfetch.oidcJwks("https://bigsquid.auth0.com").then(function (jwks) {
  console.log(jwks);
  return keyfetch.oidcJwk(jwks[0].thumbprint, "https://bigsquid.auth0.com").then(function (jwk) {
    console.log(jwk);
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
