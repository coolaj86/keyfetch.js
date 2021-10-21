"use strict";

// Possible User Errors

/**
 * @typedef AuthError
 * @property {string} message
 * @property {number} status
 * @property {string} code
 * @property {any} [details]
 */

/**
 * @param {string} msg
 * @param {{
 *   status: number,
 *   code: string,
 *   details?: any,
 * }} opts
 * @returns {AuthError}
 */
function create(old, msg, code, status, details) {
    /** @type AuthError */
    //@ts-ignore
    let err = new Error(msg);
    err.message = msg;
    err._old_message = old;
    err.code = code;
    err.status = status;
    if (details) {
        err.details = details;
    }
    err.source = "keyfetch";
    err.toJSON = toJSON;
    err.toString = toString;
    return err;
}

function toJSON() {
    /*jshint validthis:true*/
    return {
        message: this.message,
        status: this.status,
        code: this.code,
        details: this.details
    };
}
function toString() {
    /*jshint validthis:true*/
    return this.stack + "\n" + JSON.stringify(this);
}

// DEVELOPER_ERROR - a good token won't make a difference
var E_DEVELOPER = "DEVELOPER_ERROR";

// BAD_GATEWAY - there may be a temporary error fetching the public or or whatever
var E_BAD_GATEWAY = "BAD_GATEWAY";

// MALFORMED_JWT - the token could not be verified - not parsable, missing claims, etc
var E_MALFORMED = "MALFORMED_JWT";

// INVALID_JWT - the token's properties don't meet requirements - iss, claims, sig, exp
var E_INVALID = "INVALID_JWT";

module.exports = {
    //
    // DEVELOPER_ERROR (dev / server)
    //

    /**
     * @param {string} msg
     * @returns {AuthError}
     */
    DEVELOPER_ERROR: function (old, msg, details) {
        return create(old, msg || old, E_DEVELOPER, 500, details);
    },
    BAD_GATEWAY: function (err) {
        var msg =
            "The token could not be verified because our server encountered a network error (or a bad gateway) when connecting to its issuing server.";
        var details = [];
        if (err.message) {
            details.push("error.message = " + err.message);
        }
        if (err.response && err.response.statusCode) {
            details.push("response.statusCode = " + err.response.statusCode);
        }
        return create(msg, msg, E_BAD_GATEWAY, 502, details);
    },

    //
    // MALFORMED_TOKEN (dev / client)
    //

    /**
     * @param {string} iss
     * @returns {AuthError}
     */
    INSECURE_ISSUER: function (iss) {
        var old =
            "'" + iss + "' is NOT secure. Set env 'KEYFETCH_ALLOW_INSECURE_HTTP=true' to allow for testing. (iss)";
        var details = [
            "jwt.claims.iss = " + JSON.stringify(iss),
            "DEBUG: Set ENV 'KEYFETCH_ALLOW_INSECURE_HTTP=true' to allow insecure issuers (for testing)."
        ];
        var msg =
            'The token could not be verified because our server could connect to its issuing server ("iss") securely.';
        return create(old, msg, E_MALFORMED, 400, details);
    },
    /**
     * @param {string} jwt
     * @returns {AuthError}
     */
    PARSE_ERROR: function (jwt) {
        var old = "could not parse jwt: '" + jwt + "'";
        var msg = "The auth token is malformed.";
        var details = ["jwt = " + JSON.stringify(jwt)];
        return create(old, msg, E_MALFORMED, 400, details);
    },
    /**
     * @param {string} iss
     * @returns {AuthError}
     */
    NO_ISSUER: function (iss) {
        var old = "'iss' is not defined";
        var msg = 'The token could not be verified because it doesn\'t specify an issuer ("iss").';
        var details = ["jwt.claims.iss = " + JSON.stringify(iss)];
        return create(old, msg, E_MALFORMED, 400, details);
    },

    /**
     * @param {string} iss
     * @returns {AuthError}
     */
    MALFORMED_EXP: function (exp) {
        var old = "token's 'exp' has passed or could not parsed: '" + exp + "'";
        var msg = 'The auth token could not be verified because it\'s expiration date ("exp") could not be read';
        var details = ["jwt.claims.exp = " + JSON.stringify(exp)];
        return create(old, msg, E_MALFORMED, 400, details);
    },

    //
    // INVALID_TOKEN (dev / client)
    //

    /**
     * @param {number} exp
     * @returns {AuthError}
     */
    EXPIRED: function (exp) {
        var old = "token's 'exp' has passed or could not parsed: '" + exp + "'";
        // var msg = "The auth token did not pass verification because it is expired.not properly signed.";
        var msg = "The auth token is expired. To try again, go to the main page and sign in.";
        var details = ["jwt.claims.exp = " + JSON.stringify(exp)];
        return create(old, msg, E_INVALID, 401, details);
    },
    /**
     * @param {number} nbf
     * @returns {AuthError}
     */
    INACTIVE: function (nbf) {
        var old = "token's 'nbf' has not been reached or could not parsed: '" + nbf + "'";
        var msg = "The auth token isn't valid yet. It's activation date (\"nbf\") is in the future.";
        var details = ["jwt.claims.nbf = " + JSON.stringify(nbf)];
        return create(old, msg, E_INVALID, 401, details);
    },
    /** @returns {AuthError} */
    BAD_SIGNATURE: function (jwt) {
        var old = "token signature verification was unsuccessful";
        var msg = "The auth token did not pass verification because it is not properly signed.";
        var details = ["jwt = " + JSON.stringify(jwt)];
        return create(old, msg, E_INVALID, 401, details);
    },
    /**
     * @param {string} kid
     * @returns {AuthError}
     */
    JWK_NOT_FOUND_OLD: function (kid) {
        var old = "Retrieved a list of keys, but none of them matched the 'kid' (key id) of the token.";
        var msg =
            'The auth token did not pass verification because our server couldn\'t find a mutually trusted verification key ("jwk").';
        var details = ["jws.header.kid = " + JSON.stringify(kid)];
        return create(old, msg, E_INVALID, 401, details);
    },
    /**
     * @param {string} id
     * @returns {AuthError}
     */
    JWK_NOT_FOUND: function (id) {
        // TODO Distinguish between when it's a kid vs thumbprint.
        var old = "No JWK found by kid or thumbprint '" + id + "'";
        var msg =
            'The auth token did not pass verification because our server couldn\'t find a mutually trusted verification key ("jwk").';
        var details = ["jws.header.kid = " + JSON.stringify(id)];
        return create(old, msg, E_INVALID, 401, details);
    },
    /** @returns {AuthError} */
    NO_JWKWS_URI: function (url) {
        var old = "Failed to retrieve openid configuration";
        var msg =
            'The auth token did not pass verification because its issuing server did not list any verification keys ("jwks").';
        var details = ["OpenID Provider Configuration: " + JSON.stringify(url)];
        return create(old, msg, E_INVALID, 401, details);
    },
    /**
     * @param {string} iss
     * @returns {AuthError}
     */
    UNKNOWN_ISSUER: function (iss) {
        var old = "token was issued by an untrusted issuer: '" + iss + "'";
        var msg = "The auth token did not pass verification because it wasn't issued by a server that we trust.";
        var details = ["jwt.claims.iss = " + JSON.stringify(iss)];
        return create(old, msg, E_INVALID, 401, details);
    },
    /**
     * @param {Array<string>} details
     * @returns {AuthError}
     */
    FAILED_CLAIMS: function (details, claimNames) {
        var old = "token did not match on one or more authorization claims: '" + claimNames + "'";
        var msg =
            'The auth token did not pass verification because it failed some of the verification criteria ("claims").';
        return create(old, msg, E_INVALID, 401, details);
    }
};
var Errors = module.exports;

// for README
if (require.main === module) {
    console.info("| Hint | Code | Status | Message (truncated) |");
    console.info("| ---- | ---- | ------ | ------------------- |");
    Object.keys(module.exports).forEach(function (k) {
        //@ts-ignore
        var E = module.exports[k];
        var e = E("test");
        var code = e.code;
        var msg = e.message.slice(0, 45);
        var hint = k.toLowerCase().replace(/_/g, " ");
        console.info(`| (${hint}) | ${code} | ${e.status} | ${msg}... |`);
    });
    console.log(Errors.MALFORMED_EXP());
    console.log(JSON.stringify(Errors.MALFORMED_EXP(), null, 2));
}
