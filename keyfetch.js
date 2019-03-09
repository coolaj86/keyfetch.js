'use strict';

var keyfetch = module.exports;

var promisify = require('util').promisify;
var requestAsync = promisify(require('@coolaj86/urequest'));
var Rasha = require('rasha');
var Eckles = require('eckles');
var mincache = 1 * 60 * 60;
var maxcache = 3 * 24 * 60 * 60;
var staletime = 15 * 60;
var keyCache = {};

/*global Promise*/
function checkMinDefaultMax(opts, key, n, d, x) {
  var i = opts[key];
  if (!i && 0 !== i) { return d; }
  if (i >= n && i >= x) {
    return parseInt(i, 10);
  } else {
    throw new Error("opts." + key + " should be at least " + n + " and at most " + x + ", not " + i);
  }
}

keyfetch._clear = function () {
  keyCache = {};
};
keyfetch.init = function (opts) {
  mincache = checkMinDefaultMax(opts, 'mincache',
    1 * 60,
    mincache,
    31 * 24 * 60 * 60
  );
  maxcache = checkMinDefaultMax(opts, 'maxcache',
    1 * 60 * 60,
    maxcache,
    31 * 24 * 60 * 60
  );
  staletime = checkMinDefaultMax(opts, 'staletime',
    1 * 60,
    staletime,
    31 * 24 * 60 * 60
  );
};
keyfetch._oidc = function (iss) {
  return Promise.resolve().then(function () {
    return requestAsync({
      url: normalizeIss(iss) + '/.well-known/openid-configuration'
    , json: true
    }).then(function (resp) {
      var oidcConf = resp.body;
      if (!oidcConf.jwks_uri) {
        throw new Error("Failed to retrieve openid configuration");
      }
      return oidcConf;
    });
  });
};
keyfetch._wellKnownJwks = function (iss) {
  return Promise.resolve().then(function () {
    return keyfetch._jwks(normalizeIss(iss) + '/.well-known/jwks.json');
  });
};
keyfetch._jwks = function (iss) {
  return requestAsync({ url: iss, json: true }).then(function (resp) {
    return Promise.all(resp.body.keys.map(function (jwk) {
      // EC keys have an x values, whereas RSA keys do not
      var Keypairs = jwk.x ? Eckles : Rasha;
      return Keypairs.thumbprint({ jwk: jwk }).then(function (thumbprint) {
        return Keypairs.export({ jwk: jwk }).then(function (pem) {
          var cacheable = {
            jwk: jwk
          , thumbprint: thumbprint
          , pem: pem
          };
          return cacheable;
        });
      });
    }));
  });
};
keyfetch.jwks = function (jwkUrl) {
  // TODO DRY up a bit
  return keyfetch._jwks(jwkUrl).then(function (results) {
    return Promise.all(results.map(function (result) {
      return keyfetch._setCache(result.jwk.iss || jwkUrl, result);
    })).then(function () {
      // cacheable -> hit (keep original externally immutable)
      return JSON.parse(JSON.stringify(results));
    });
  });
};
keyfetch.wellKnownJwks = function (iss) {
  // TODO DRY up a bit
  return keyfetch._wellKnownJwks(iss).then(function (results) {
    return Promise.all(results.map(function (result) {
      return keyfetch._setCache(result.jwk.iss || iss, result);
    })).then(function () {
      // result -> hit (keep original externally immutable)
      return JSON.parse(JSON.stringify(results));
    });
  });
};
keyfetch.oidcJwks = function (iss) {
  return keyfetch._oidc(iss).then(function (oidcConf) {
    // TODO DRY up a bit
    return keyfetch._jwks(oidcConf.jwks_uri).then(function (results) {
      return Promise.all(results.map(function (result) {
        return keyfetch._setCache(result.jwk.iss || iss, result);
      })).then(function () {
        // result -> hit (keep original externally immutable)
        return JSON.parse(JSON.stringify(results));
      });
    });
  });
};
function checkId(id) {
  return function (results) {
    var result = results.filter(function (result) {
      // we already checked iss above
      return result.jwk.kid === id || result.thumbprint === id;
    })[0];

    if (!result) {
      throw new Error("No JWK found by kid or thumbprint '" + id + "'");
    }
    return result;
  };
}
keyfetch.oidcJwk = function (id, iss) {
  return keyfetch._checkCache(id, iss).then(function (hit) {
    if (hit) { return hit; }
    return keyfetch.oidcJwks(iss).then(checkId(id));
  });
};
keyfetch.wellKnownJwk = function (id, iss) {
  return keyfetch._checkCache(id, iss).then(function (hit) {
    if (hit) { return hit; }
    return keyfetch.wellKnownJwks(iss).then(checkId(id));
  });
};
keyfetch.jwk = function (id, jwksUrl) {
  return keyfetch._checkCache(id, jwksUrl).then(function (hit) {
    if (hit) { return hit; }
    return keyfetch.jwks(jwksUrl).then(checkId(id));
  });
};
keyfetch._checkCache = function (id, iss) {
  return Promise.resolve().then(function () {
    // We cache by thumbprint and (kid + '@' + iss),
    // so it's safe to check without appending the issuer
    var hit = keyCache[id];
    if (!hit) {
      hit = keyCache[id + '@' + normalizeIss(iss)];
    }
    if (!hit) {
      return null;
    }

    var now = Math.round(Date.now() / 1000);
    var left = hit.expiresAt - now;
    // not guarding number checks since we know that we
    // set 'now' and 'expiresAt' correctly elsewhere
    if (left > staletime) {
      return JSON.parse(JSON.stringify(hit));
    }
    if (left > 0) {
      return JSON.parse(JSON.stringify(hit));
    }
    return null;
  });
};
keyfetch._setCache = function (iss, cacheable) {
  // force into a number
  var expiresAt = parseInt(cacheable.jwk.exp, 10) || 0;
  var now = Date.now() / 1000;
  var left = expiresAt - now;

  // TODO maybe log out when any of these non-ideal cases happen?
  if (!left) {
    expiresAt = now + maxcache;
  } else if (left < mincache) {
    expiresAt = now + mincache;
  } else if (left > maxcache) {
    expiresAt = now + maxcache;
  }

  // cacheable = { jwk, thumprint, pem }
  cacheable.createdAt = now;
  cacheable.expiresAt = expiresAt;
  keyCache[cacheable.thumbprint] = cacheable;
  keyCache[cacheable.jwk.kid + '@' + normalizeIss(iss)] = cacheable;
};

function normalizeIss(iss) {
  // We definitely don't want false negatives stemming
  // from https://example.com vs https://example.com/
  // We also don't want to allow insecure issuers
  if (/^http:/.test(iss) && !process.env.KEYFETCH_ALLOW_INSECURE_HTTP) {
    // note, we wrap some things in promises just so we can throw here
    throw new Error("'" + iss + "' is NOT secure. Set env 'KEYFETCH_ALLOW_INSECURE_HTTP=true' to allow for testing.");
  }
  return iss.replace(/\/$/, '');
}
keyfetch._decode = function (jwt) {
  var parts = jwt.split('.');
  return {
    header: JSON.parse(Buffer.from(parts[0], 'base64'))
  , payload: JSON.parse(Buffer.from(parts[1], 'base64'))
  , signature: parts[2] //Buffer.from(parts[2], 'base64')
  };
};
keyfetch.verify = function (opts) {
  var jwt = opts.jwt;
  return Promise.resolve().then(function () {
    var decoded;
    var exp;
    var nbf;
    var valid;
    try {
      decoded = keyfetch._decode(jwt);
      exp = decoded.payload.exp;
      nbf = decoded.payload.nbf;
    } catch (e) {
      throw new Error("could not parse opts.jwt: '" + jwt + "'");
    }
    if (exp) {
      valid = (parseInt(exp, 10) - (Date.now()/1000) > 0);
      if (!valid) {
        throw new Error("token's 'exp' has passed or could not parsed: '" + exp + "'");
      }
    }
    if (nbf) {
      valid = (parseInt(nbf, 10) - (Date.now()/1000) <= 0);
      if (!valid) {
        throw new Error("token's 'nbf' has not been reached or could not parsed: '" + nbf + "'");
      }
    }
    var kid = decoded.header.kid;
    var iss;
    var fetcher;
    var fetchOne;
    if (!opts.strategy || 'oidc' === opts.strategy) {
      iss = decoded.payload.iss;
      fetcher = keyfetch.oidcJwks;
      fetchOne = keyfetch.oidcJwk;
    } else if ('auth0' === opts.strategy || 'well-known' === opts.strategy) {
      iss = decoded.payload.iss;
      fetcher = keyfetch.wellKnownJwks;
      fetchOne = keyfetch.wellKnownJwk;
    } else {
      iss = opts.strategy;
      fetcher = keyfetch.jwks;
      fetchOne = keyfetch.jwk;
    }

    function verify(jwk, payload) {
      var alg = 'SHA' + decoded.header.alg.replace(/[^\d]+/i, '');
      var sig = convertIfEcdsa(decoded.header, decoded.signature);
      return require('crypto')
        .createVerify(alg)
        .update(jwt.split('.')[0] + '.' + payload)
        .verify(jwk.pem, sig, 'base64');
    }

    function convertIfEcdsa(header, b64sig) {
      // ECDSA JWT signatures differ from "normal" ECDSA signatures
      // https://tools.ietf.org/html/rfc7518#section-3.4
      if (!/^ES/i.test(header.alg)) { return b64sig; }

      var bufsig = Buffer.from(b64sig, 'base64');
      var hlen = bufsig.byteLength / 2; // should be even
      var r = bufsig.slice(0, hlen);
      var s = bufsig.slice(hlen);
      // pad ambiguously non-negative BigInts
      if (0x80 & r[0]) { r = Buffer.concat([Buffer.from([0]), r]); }
      if (0x80 & s[0]) { s = Buffer.concat([Buffer.from([0]), s]); }

      var len = 2 + r.byteLength + 2 + s.byteLength;
      var head = [0x30];
      // hard code 0x80 + 1 because it won't be longer than
      // two SHA512 plus two pad bytes (130 bytes <= 256)
      if (len >= 0x80) { head.push(0x81); }
      head.push(len);

      var buf = Buffer.concat([
        Buffer.from(head)
      , Buffer.from([0x02, r.byteLength]), r
      , Buffer.from([0x02, r.byteLength]), s
      ]);

      return buf.toString('base64')
        .replace(/-/g, '+')
        .replace(/_/g, '/')
        .replace(/=/g, '')
      ;
    }

    var payload = jwt.split('.')[1]; // as string, as it was signed
    if (kid) {
      return fetchOne(kid, iss).then(verifyOne); //.catch(fetchAny);
    } else {
      return fetchAny();
    }

    function verifyOne(jwk) {
      if (verify(jwk, payload)) {
        return decoded;
      }
      throw new Error('token signature verification was unsuccessful');
    }

    function fetchAny() {
      return fetcher(iss).then(function (jwks) {
        if (jwks.some(function (jwk) {
          if (kid) {
            if (kid !== jwk.kid && kid !== jwk.thumbprint) { return; }
            if (verify(jwk, payload)) { return true; }
            throw new Error('token signature verification was unsuccessful');
          } else {
            if (verify(jwk, payload)) { return true; }
          }
        })) {
          return decoded;
        }
        throw new Error("Retrieved a list of keys, but none of them matched the 'kid' (key id) of the token.");
      });
    }
  });
};
