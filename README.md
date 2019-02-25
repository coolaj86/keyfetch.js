# keyfetch

Lightweight support for fetching JWKs.

Fetches JSON native JWKs and exposes them as PEMs that can be consumed by the `jsonwebtoken` package
(and node's native RSA and ECDSA crypto APIs).

## Features

Works great for

* [x] `jsonwebtoken` (Auth0)
* [x] OIDC (OpenID Connect)
* [x] .well-known/jwks.json (Auth0)
* [x] Other JWKs URLs

Crypto Support

* [x] JWT verification
* [x] RSA (all variants)
* [x] EC / ECDSA (NIST variants P-256, P-384)
* [ ] esoteric variants (excluded to keep the code featherweight and secure)

# Install

```bash
npm install --save keyfetch
```

# Usage

Retrieve a key list of keys:

```js
var keyfetch = require('keyfetch');

keyfetch.oidcJwks("https://example.com/").then(function (results) {
  results.forEach(function (result) {
    console.log(result.jwk);
    console.log(result.thumprint);
    console.log(result.pem);
  });
});
```

Quick JWT verification:

```js
var keyfetch = require('keyfetch');
var jwt = '...';

keyfetch.verify({ jwt: jwt }).then(function (decoded) {
  console.log(decoded);
});
```

Verify a JWT with `jsonwebtoken`:

```js
var keyfetch = require('keyfetch');
var jwt = require('jsonwebtoken');
var auth = "..."; // some JWT
var token = jwt.decode(auth, { json: true, complete: true })

if (!isTrustedIssuer(token.payload.iss)) {
  throw new Error("untrusted issuer");
}

keyfetch.oidcJwk(
  token.header.kid
, token.payload.iss
).then(function (result) {
  console.log(result.jwk);
  console.log(result.thumprint);
  console.log(result.pem);

  jwt.verify(jwt, pem);
});
```

*Note*: You might implement `isTrustedIssuer` one of these:

```js
function isTrustedIssuer(iss) {
  return -1 !== [ 'https://partner.com/', 'https://auth0.com/'].indexOf(iss);
}
```

```js
function isTrustedIssuer(iss) {
  return /^https:/.test(iss) &&         // must be a secure domain
    /(\.|^)example\.com$/.test(iss);    // can be example.com or any subdomain
}
```

# API

All API calls will return the RFC standard JWK SHA256 thumbprint as well as a PEM version of the key.

Note: When specifying `id`, it may be either `kid` (as in `token.header.kid`)
or `thumbprint` (as in `result.thumbprint`).

### JWKs URLs

Retrieves keys from a URL such as `https://example.com/jwks/` with the format `{ keys: [ { kid, kty, exp, ... } ] }`
and returns the array of keys (as well as thumbprint and jwk-to-pem).

```js
keyfetch.jwks(jwksUrl)
// Promises [ { jwk, thumbprint, pem } ] or fails
```

```js
keyfetch.jwk(id, jwksUrl)
// Promises { jwk, thumbprint, pem } or fails
```

### Auth0

If `https://example.com/` is used as `issuerUrl` it will resolve to
`https://example.com/.well-known/jwks.json` and return the keys.

```js
keyfetch.wellKnownJwks(issuerUrl)
// Promises [ { jwk, thumbprint, pem } ] or fails
```

```js
keyfetch.wellKnownJwk(id, issuerUrl)
// Promises { jwk, thumbprint, pem } or fails
```

### OIDC

If `https://example.com/` is used as `issuerUrl` then it will first resolve to
`https://example.com/.well-known/openid-configuration` and then follow `jwks_uri` to return the keys.

```js
keyfetch.oidcJwks(issuerUrl)
// Promises [ { jwk, thumbprint, pem } ] or fails
```

```js
keyfetch.oidcJwk(id, issuerUrl)
// Promises { jwk, thumbprint, pem } or fails
```

### Verify JWT

```js
keyfetch.verify({ jwt: jwk, strategy: 'oidc' })
// Promises a decoded JWT { headers, payload, signature } or fails
```

* `strategy` may be `oidc` (default) , `auth0`, or a direct JWKs url.

### Cache Settings

```js
keyfetch.init({
  // set all keys at least 1 hour (regardless of jwk.exp)
  mincache: 1 * 60 * 60

  // expire each key after 3 days (regardless of jwk.exp)
, maxcache: 3 * 24 * 60 * 60

  // re-fetch a key up to 15 minutes before it expires (only if used)
, staletime: 15 * 60
})
```

There is no background task to cleanup expired keys as of yet.
For now you can limit the number of keys fetched by having a simple whitelist.
