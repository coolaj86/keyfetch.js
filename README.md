# [keyfetch](https://git.rootprojects.org/root/keyfetch.js)

Lightweight support for fetching JWKs.

Fetches JSON native JWKs and exposes them as PEMs that can be consumed by the `jsonwebtoken` package
(and node's native RSA and ECDSA crypto APIs).

## Features

Works great for

-   [x] `jsonwebtoken` (Auth0)
-   [x] OIDC (OpenID Connect)
-   [x] .well-known/jwks.json (Auth0, Okta)
-   [x] Other JWKs URLs

Crypto Support

-   [x] JWT verification
-   [x] RSA (all variants)
-   [x] EC / ECDSA (NIST variants P-256, P-384)
-   [x] Sane error codes
-   [ ] esoteric variants (excluded to keep the code featherweight and secure)

# Table of Contents

-   Install
-   Usage
-   API
    -   Auth0 / Okta
    -   OIDC
-   Errors
-   Change Log

# Install

```bash
npm install --save keyfetch
```

# Usage

Retrieve a key list of keys:

```js
var keyfetch = require("keyfetch");

keyfetch.oidcJwks("https://example.com/").then(function (results) {
    results.forEach(function (result) {
        console.log(result.jwk);
        console.log(result.thumprint);
        console.log(result.pem);
    });
});
```

Quick JWT verification (for authentication):

```js
var keyfetch = require("keyfetch");
var jwt = "...";

keyfetch.jwt.verify(jwt).then(function (decoded) {
    console.log(decoded);
});
```

JWT verification (for authorization):

```js
var options = { issuers: ["https://example.com/"], claims: { role: "admin" } };
keyfetch.jwt.verify(jwt, options).then(function (decoded) {
    console.log(decoded);
});
```

Verify a JWT with `jsonwebtoken`:

```js
var keyfetch = require("keyfetch");
var jwt = require("jsonwebtoken");
var auth = "..."; // some JWT
var token = jwt.decode(auth, { json: true, complete: true });

if (!isTrustedIssuer(token.payload.iss)) {
    throw new Error("untrusted issuer");
}

keyfetch.oidcJwk(token.header.kid, token.payload.iss).then(function (result) {
    console.log(result.jwk);
    console.log(result.thumprint);
    console.log(result.pem);

    jwt.jwt.verify(jwt, { jwk: result.jwk });
});
```

_Note_: You might implement `isTrustedIssuer` one of these:

```js
function isTrustedIssuer(iss) {
    return -1 !== ["https://partner.com/", "https://auth0.com/"].indexOf(iss);
}
```

```js
function isTrustedIssuer(iss) {
    return (
        /^https:/.test(iss) && /(\.|^)example\.com$/.test(iss) // must be a secure domain
    ); // can be example.com or any subdomain
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
keyfetch.jwks(jwksUrl);
// Promises [ { jwk, thumbprint, pem } ] or fails
```

```js
keyfetch.jwk(id, jwksUrl);
// Promises { jwk, thumbprint, pem } or fails
```

### Auth0

If `https://example.com/` is used as `issuerUrl` it will resolve to
`https://example.com/.well-known/jwks.json` and return the keys.

```js
keyfetch.wellKnownJwks(issuerUrl);
// Promises [ { jwk, thumbprint, pem } ] or fails
```

```js
keyfetch.wellKnownJwk(id, issuerUrl);
// Promises { jwk, thumbprint, pem } or fails
```

### OIDC

If `https://example.com/` is used as `issuerUrl` then it will first resolve to
`https://example.com/.well-known/openid-configuration` and then follow `jwks_uri` to return the keys.

```js
keyfetch.oidcJwks(issuerUrl);
// Promises [ { jwk, thumbprint, pem } ] or fails
```

```js
keyfetch.oidcJwk(id, issuerUrl);
// Promises { jwk, thumbprint, pem } or fails
```

### Verify JWT

This can accept a _JWT string_ (compact JWS) or a _decoded JWT object_ (JWS).

This can be used purely for verifying pure authentication tokens, as well as authorization tokens.

```js
keyfetch.jwt.verify(jwt, { strategy: "oidc" }).then(function (verified) {
    /*
    { protected: '...'  // base64 header
    , payload: '...'    // base64 payload
    , signature: '...'  // base64 signature
    , header: {...}     // decoded header
    , claims: {...}     // decoded payload
    }
  */
});
```

When used for authorization, it's important to specify a limited set of trusted `issuers`. \
When using for federated authentication you may set `issuers = ["*"]` - but **DO NOT** trust claims such as `email` and `email_verified`.

If your authorization `claims` can be expressed as exact string matches, you can specify those too.

```js
keyfetch.jwt.verify(jwt, {
  strategy: 'oidc',
  issuers: [ 'https://example.com/' ],
  //iss: 'https://example.com/',
  claims: { role: 'admin', sub: 'abc', group: 'xyz' }
}).then(function (verified) {
```

-   `strategy` may be `oidc` (default) , `auth0`, or a direct JWKs url.
-   `issuers` must be a list of https urls (though http is allowed for things like Docker swarm), or '\*'
-   `iss` is like `issuers`, but only one
-   `claims` is an object with arbitrary keys (i.e. everything except for the standard `iat`, `exp`, `jti`, etc)
-   `exp` may be set to `false` if you're validating on your own (i.e. allowing time drift leeway)
-   `jwks` can be used to specify a list of allowed public key rather than fetching them (i.e. for offline unit tests)
-   `jwk` same as above, but a single key rather than a list

### Decode JWT

```jwt
try {
  console.log( keyfetch.jwt.decode(jwt) );
} catch(e) {
  console.error(e);
}
```

```js
{ protected: '...'  // base64 header
, payload: '...'    // base64 payload
, signature: '...'  // base64 signature
, header: {...}     // decoded header
, claims: {...}     // decoded payload
```

It's easier just to show the code than to explain the example.

```js
keyfetch.jwt.decode = function (jwt) {
    // Unpack JWS from "compact" form
    var parts = jwt.split(".");
    var obj = {
        protected: parts[0],
        payload: parts[1],
        signature: parts[2]
    };

    // Decode JWT properties from JWS as unordered objects
    obj.header = JSON.parse(Buffer.from(obj.protected, "base64"));
    obj.claims = JSON.parse(Buffer.from(obj.payload, "base64"));

    return obj;
};
```

### Cache Settings

```js
keyfetch.init({
    // set all keys at least 1 hour (regardless of jwk.exp)
    mincache: 1 * 60 * 60,

    // expire each key after 3 days (regardless of jwk.exp)
    maxcache: 3 * 24 * 60 * 60,

    // re-fetch a key up to 15 minutes before it expires (only if used)
    staletime: 15 * 60
});
```

There is no background task to cleanup expired keys as of yet.
For now you can limit the number of keys fetched by having a simple whitelist.

# Errors

`JSON.stringify()`d errors look like this:

```js
{
  code: "INVALID_JWT",
  status: 401,
  details: [ "jwt.claims.exp = 1634804500", "DEBUG: helpful message" ]
  message: "token's 'exp' has passed or could not parsed: 1634804500"
}
```

SemVer Compatibility:

-   `code` & `status` will remain the same.
-   `message` is **NOT** included in the semver compatibility guarantee (we intend to make them more client-friendly), neither is `detail` at this time (but it will be once we decide on what it should be).
-   `details` may be added to, but not subtracted from

| Hint              | Code          | Status | Message (truncated)                                    |
| ----------------- | ------------- | ------ | ------------------------------------------------------ |
| bad gateway       | BAD_GATEWAY   | 502    | The auth token could not be verified because our se... |
| insecure issuer   | MALFORMED_JWT | 400    | The auth token could not be verified because our se... |
| parse error       | MALFORMED_JWT | 400    | The auth token could not be verified because it is ... |
| no issuer         | MALFORMED_JWT | 400    | The auth token could not be verified because it doe... |
| malformed exp     | MALFORMED_JWT | 400    | The auth token could not be verified because it's e... |
| expired           | INVALID_JWT   | 401    | The auth token is expired. To try again, go to the ... |
| inactive          | INVALID_JWT   | 401    | The auth token isn't valid yet. It's activation dat... |
| bad signature     | INVALID_JWT   | 401    | The auth token did not pass verification because it... |
| jwk not found old | INVALID_JWT   | 401    | The auth token did not pass verification because ou... |
| jwk not found     | INVALID_JWT   | 401    | The auth token did not pass verification because ou... |
| no jwkws uri      | INVALID_JWT   | 401    | The auth token did not pass verification because it... |
| unknown issuer    | INVALID_JWT   | 401    | The auth token did not pass verification because it... |
| failed claims     | INVALID_JWT   | 401    | The auth token did not pass verification because it... |

# Change Log

Minor Breaking changes (with a major version bump):

-   v3.0.0
    -   reworked error messages (also available in v2.1.0 as `client_message`)
    -   started using `let` and template strings (drops _really_ old node compat)
-   v2.0.0
    -   changes from the default `issuers = ["*"]` to requiring that an issuer (or public jwk for verification) is specified

See other changes in [CHANGELOG.md](./CHANGELOG.md).
