"use strict";

var keyfetch = module.exports;

var request = require("@root/request").defaults({
    userAgent: "keyfetch/v2.1.0"
});
var Rasha = require("rasha");
var Eckles = require("eckles");
var mincache = 1 * 60 * 60;
var maxcache = 3 * 24 * 60 * 60;
var staletime = 15 * 60;
var keyCache = {};

var Errors = require("./lib/errors.js");

async function requestAsync(req) {
    var resp = await request(req).catch(Errors.BAD_GATEWAY);

    // differentiate potentially temporary server errors from 404
    if (!resp.ok && (resp.statusCode >= 500 || resp.statusCode < 200)) {
        throw Errors.BAD_GATEWAY({ response: resp });
    }

    return resp;
}

function checkMinDefaultMax(opts, key, n, d, x) {
    var i = opts[key];
    if (!i && 0 !== i) {
        return d;
    }
    if (i >= n && i >= x) {
        return parseInt(i, 10);
    } else {
        throw Errors.DEVELOPER_ERROR("opts." + key + " should be at least " + n + " and at most " + x + ", not " + i);
    }
}

keyfetch._errors = Errors;

keyfetch._clear = function () {
    keyCache = {};
};
keyfetch.init = function (opts) {
    mincache = checkMinDefaultMax(opts, "mincache", 1 * 60, mincache, 31 * 24 * 60 * 60);
    maxcache = checkMinDefaultMax(opts, "maxcache", 1 * 60 * 60, maxcache, 31 * 24 * 60 * 60);
    staletime = checkMinDefaultMax(opts, "staletime", 1 * 60, staletime, 31 * 24 * 60 * 60);
};
keyfetch._oidc = async function (iss) {
    var url = normalizeIss(iss) + "/.well-known/openid-configuration";
    var resp = await requestAsync({
        url: url,
        json: true
    });

    var oidcConf = resp.body;
    if (!oidcConf.jwks_uri) {
        throw Errors.NO_JWKS_URI(url);
    }
    return oidcConf;
};
keyfetch._wellKnownJwks = async function (iss) {
    return keyfetch._jwks(normalizeIss(iss) + "/.well-known/jwks.json");
};
keyfetch._jwks = async function (iss) {
    var resp = await requestAsync({ url: iss, json: true });

    return Promise.all(
        resp.body.keys.map(async function (jwk) {
            // EC keys have an x values, whereas RSA keys do not
            var Keypairs = jwk.x ? Eckles : Rasha;
            var thumbprint = await Keypairs.thumbprint({ jwk: jwk });
            var pem = await Keypairs.export({ jwk: jwk });
            var cacheable = {
                jwk: jwk,
                thumbprint: thumbprint,
                pem: pem
            };
            return cacheable;
        })
    );
};
keyfetch.jwks = async function (jwkUrl) {
    // TODO DRY up a bit
    var results = await keyfetch._jwks(jwkUrl);
    await Promise.all(
        results.map(async function (result) {
            return keyfetch._setCache(result.jwk.iss || jwkUrl, result);
        })
    );
    // cacheable -> hit (keep original externally immutable)
    return JSON.parse(JSON.stringify(results));
};
keyfetch.wellKnownJwks = async function (iss) {
    // TODO DRY up a bit
    var results = await keyfetch._wellKnownJwks(iss);
    await Promise.all(
        results.map(async function (result) {
            return keyfetch._setCache(result.jwk.iss || iss, result);
        })
    );
    // result -> hit (keep original externally immutable)
    return JSON.parse(JSON.stringify(results));
};
keyfetch.oidcJwks = async function (iss) {
    var oidcConf = await keyfetch._oidc(iss);
    // TODO DRY up a bit
    var results = await keyfetch._jwks(oidcConf.jwks_uri);
    await Promise.all(
        results.map(async function (result) {
            return keyfetch._setCache(result.jwk.iss || iss, result);
        })
    );
    // result -> hit (keep original externally immutable)
    return JSON.parse(JSON.stringify(results));
};
function checkId(id) {
    return function (results) {
        var result = results.filter(function (result) {
            // we already checked iss above
            return result.jwk.kid === id || result.thumbprint === id;
        })[0];

        if (!result) {
            throw Errors.JWK_NOT_FOUND(id);
        }
        return result;
    };
}
keyfetch.oidcJwk = async function (id, iss) {
    var hit = await keyfetch._checkCache(id, iss);
    if (hit) {
        return hit;
    }
    return keyfetch.oidcJwks(iss).then(checkId(id));
};
keyfetch.wellKnownJwk = async function (id, iss) {
    var hit = await keyfetch._checkCache(id, iss);
    if (hit) {
        return hit;
    }
    return keyfetch.wellKnownJwks(iss).then(checkId(id));
};
keyfetch.jwk = async function (id, jwksUrl) {
    var hit = await keyfetch._checkCache(id, jwksUrl);
    if (hit) {
        return hit;
    }
    return keyfetch.jwks(jwksUrl).then(checkId(id));
};
keyfetch._checkCache = async function (id, iss) {
    // We cache by thumbprint and (kid + '@' + iss),
    // so it's safe to check without appending the issuer
    var hit = keyCache[id];
    if (!hit) {
        hit = keyCache[id + "@" + normalizeIss(iss)];
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
    keyCache[cacheable.jwk.kid + "@" + normalizeIss(iss)] = cacheable;
};

function normalizeIss(iss) {
    if (!iss) {
        throw Errors.NO_ISSUER();
    }

    // We definitely don't want false negatives stemming
    // from https://example.com vs https://example.com/
    // We also don't want to allow insecure issuers
    if (/^http:/.test(iss) && !process.env.KEYFETCH_ALLOW_INSECURE_HTTP) {
        // note, we wrap some things in promises just so we can throw here
        throw Errors.INSECURE_ISSUER(iss);
    }
    return iss.replace(/\/$/, "");
}

keyfetch.jwt = {};
keyfetch.jwt.decode = function (jwt) {
    try {
        var parts = jwt.split(".");
        // JWS
        var obj = { protected: parts[0], payload: parts[1], signature: parts[2] };
        // JWT
        obj.header = JSON.parse(Buffer.from(obj.protected, "base64"));
        obj.claims = JSON.parse(Buffer.from(obj.payload, "base64"));
        return obj;
    } catch (e) {
        var err = Errors.PARSE_ERROR(jwt);
        err.details = e.message;
        throw err;
    }
};
keyfetch.jwt.verify = async function (jwt, opts) {
    if (!opts) {
        opts = {};
    }

    var jws;
    var exp;
    var nbf;
    var active;
    var now;
    var then;
    var issuers = opts.issuers || [];
    if (opts.iss) {
        issuers.push(opts.iss);
    }
    if (opts.claims && opts.claims.iss) {
        issuers.push(opts.claims.iss);
    }
    if (!issuers.length) {
        if (!(opts.jwk || opts.jwks)) {
            throw Errors.DEVELOPER_ERROR(
                "[keyfetch.js] Security Error: Neither of opts.issuers nor opts.iss were provided. If you would like to bypass issuer verification (i.e. for federated authn) you must explicitly set opts.issuers = ['*']. Otherwise set a value such as https://accounts.google.com/"
            );
        }
    }
    var claims = opts.claims || {};
    if (!jwt || "string" === typeof jwt) {
        jws = keyfetch.jwt.decode(jwt);
    } else {
        jws = jwt;
    }

    if (!jws.claims.iss || !issuers.some(isTrustedIssuer(jws.claims.iss))) {
        if (!(opts.jwk || opts.jwks)) {
            throw Errors.UNKNOWN_ISSUER(jws.claims.iss || "");
        }
    }
    // Note claims.iss validates more strictly than opts.issuers (requires exact match)
    var failedClaims = Object.keys(claims)
        .filter(function (key) {
            if (claims[key] !== jws.claims[key]) {
                return true;
            }
        })
        .map(function (key) {
            return "jwt.claims." + key + " = " + JSON.stringify(jws.claims[key]);
        });
    if (failedClaims.length) {
        throw Errors.FAILED_CLAIMS(failedClaims, Object.keys(claims));
    }

    exp = jws.claims.exp;
    if (exp && false !== opts.exp) {
        now = Date.now();
        // TODO document that opts.exp can be used as leeway? Or introduce opts.leeway?
        // fair, but not necessary
        exp = parseInt(exp, 10);
        if (isNaN(exp)) {
            throw Errors.MALFORMED_EXP(JSON.stringify(jws.claims.exp));
        }
        then = (opts.exp || 0) + parseInt(exp, 10);
        active = then - now / 1000 > 0;
        // expiration was on the token or, if not, such a token is not allowed
        if (!active) {
            throw Errors.EXPIRED(exp);
        }
    }

    nbf = jws.claims.nbf;
    if (nbf) {
        active = parseInt(nbf, 10) - Date.now() / 1000 <= 0;
        if (!active) {
            throw Errors.INACTIVE(nbf);
        }
    }
    if (opts.jwks || opts.jwk) {
        return overrideLookup(opts.jwks || [opts.jwk]);
    }

    var kid = jws.header.kid;
    var iss;
    var fetcher;
    var fetchOne;
    if (!opts.strategy || "oidc" === opts.strategy) {
        iss = jws.claims.iss;
        fetcher = keyfetch.oidcJwks;
        fetchOne = keyfetch.oidcJwk;
    } else if ("auth0" === opts.strategy || "well-known" === opts.strategy) {
        iss = jws.claims.iss;
        fetcher = keyfetch.wellKnownJwks;
        fetchOne = keyfetch.wellKnownJwk;
    } else {
        iss = opts.strategy;
        fetcher = keyfetch.jwks;
        fetchOne = keyfetch.jwk;
    }

    if (kid) {
        return fetchOne(kid, iss).then(verifyOne); //.catch(fetchAny);
    }
    return fetcher(iss).then(verifyAny);

    function verifyOne(hit) {
        if (true === keyfetch.jws.verify(jws, hit)) {
            return jws;
        }
        throw Errors.BAD_SIGNATURE(jws.protected + "." + jws.payload + "." + jws.signature);
    }

    function verifyAny(hits) {
        if (
            hits.some(function (hit) {
                if (kid) {
                    if (kid !== hit.jwk.kid && kid !== hit.thumbprint) {
                        return;
                    }
                    if (true === keyfetch.jws.verify(jws, hit)) {
                        return true;
                    }
                    throw Errors.BAD_SIGNATURE();
                }
                if (true === keyfetch.jws.verify(jws, hit)) {
                    return true;
                }
            })
        ) {
            return jws;
        }
        throw Errors.JWK_NOT_FOUND_OLD(kid);
    }

    function overrideLookup(jwks) {
        return Promise.all(
            jwks.map(async function (jwk) {
                var Keypairs = jwk.x ? Eckles : Rasha;
                var pem = await Keypairs.export({ jwk: jwk });
                var thumb = await Keypairs.thumbprint({ jwk: jwk });
                return { jwk: jwk, pem: pem, thumbprint: thumb };
            })
        ).then(verifyAny);
    }
};
keyfetch.jws = {};
keyfetch.jws.verify = function (jws, pub) {
    var alg = "SHA" + jws.header.alg.replace(/[^\d]+/i, "");
    var sig = ecdsaJoseSigToAsn1Sig(jws.header, jws.signature);
    return require("crypto")
        .createVerify(alg)
        .update(jws.protected + "." + jws.payload)
        .verify(pub.pem, sig, "base64");
};

// old, gotta make sure nothing else uses this
keyfetch._decode = function (jwt) {
    var obj = keyfetch.jwt.decode(jwt);
    return { header: obj.header, payload: obj.claims, signature: obj.signature };
};
keyfetch.verify = async function (opts) {
    var jwt = opts.jwt;
    var obj = await keyfetch.jwt.verify(jwt, opts);
    return { header: obj.header, payload: obj.claims, signature: obj.signature };
};

function ecdsaJoseSigToAsn1Sig(header, b64sig) {
    // ECDSA JWT signatures differ from "normal" ECDSA signatures
    // https://tools.ietf.org/html/rfc7518#section-3.4
    if (!/^ES/i.test(header.alg)) {
        return b64sig;
    }

    var bufsig = Buffer.from(b64sig, "base64");
    var hlen = bufsig.byteLength / 2; // should be even
    var r = bufsig.slice(0, hlen);
    var s = bufsig.slice(hlen);
    // unpad positive ints less than 32 bytes wide
    while (!r[0]) {
        r = r.slice(1);
    }
    while (!s[0]) {
        s = s.slice(1);
    }
    // pad (or re-pad) ambiguously non-negative BigInts to 33 bytes wide
    if (0x80 & r[0]) {
        r = Buffer.concat([Buffer.from([0]), r]);
    }
    if (0x80 & s[0]) {
        s = Buffer.concat([Buffer.from([0]), s]);
    }

    var len = 2 + r.byteLength + 2 + s.byteLength;
    var head = [0x30];
    // hard code 0x80 + 1 because it won't be longer than
    // two SHA512 plus two pad bytes (130 bytes <= 256)
    if (len >= 0x80) {
        head.push(0x81);
    }
    head.push(len);

    var buf = Buffer.concat([
        Buffer.from(head),
        Buffer.from([0x02, r.byteLength]),
        r,
        Buffer.from([0x02, s.byteLength]),
        s
    ]);

    return buf.toString("base64").replace(/-/g, "+").replace(/_/g, "/").replace(/=/g, "");
}

function isTrustedIssuer(issuer) {
    return function (trusted) {
        if ("*" === trusted) {
            return true;
        }
        // TODO account for '*.example.com'
        trusted = /^http(s?):\/\//.test(trusted) ? trusted : "https://" + trusted;
        return issuer.replace(/\/$/, "") === trusted.replace(/\/$/, "") && trusted;
    };
}
