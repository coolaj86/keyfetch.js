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
function create(msg, { status = 401, code = "", details }) {
    /** @type AuthError */
    //@ts-ignore
    var err = new Error(msg);
    err.message = err.message;
    err.status = status;
    err.code = code;
    if (details) {
        err.details = details;
    }
    err.source = "keyfetch";
    return err;
}

// DEVELOPER_ERROR - a good token won't make a difference
var E_DEVELOPER = "DEVELOPER_ERROR";

// BAD_GATEWAY - there may be a temporary error fetching the public or or whatever
var E_BAD_GATEWAY = "BAD_GATEWAY";

// MALFORMED_TOKEN - the token could not be verified - not parsable, missing claims, etc
var E_MALFORMED = "MALFORMED_JWT";

// INVALID_TOKEN - the token's properties don't meet requirements - iss, claims, sig, exp
var E_INVALID = "INVALID_JWT";

module.exports = {
    //
    // DEVELOPER_ERROR (dev / server)
    //

    /**
     * @param {string} msg
     * @returns {AuthError}
     */
    DEVELOPER_ERROR: function (msg) {
        return create(msg, { status: 500, code: E_DEVELOPER });
    },
    BAD_GATEWAY: function (/*err*/) {
        var msg = "The server encountered a network error or a bad gateway.";
        return create(msg, { status: 502, code: E_BAD_GATEWAY });
    },

    //
    // MALFORMED_TOKEN (dev / client)
    //

    /**
     * @param {string} iss
     * @returns {AuthError}
     */
    INSECURE_ISSUER: function (iss) {
        var msg =
            "'" + iss + "' is NOT secure. Set env 'KEYFETCH_ALLOW_INSECURE_HTTP=true' to allow for testing. (iss)";
        return create(msg, { status: 400, code: E_MALFORMED });
    },
    /**
     * @param {string} jwt
     * @returns {AuthError}
     */
    TOKEN_PARSE_ERROR: function (jwt) {
        var msg = "could not parse jwt: '" + jwt + "'";
        return create(msg, { status: 400, code: E_MALFORMED });
    },
    /**
     * @param {string} iss
     * @returns {AuthError}
     */
    TOKEN_NO_ISSUER: function (iss) {
        var msg = "'iss' is not defined";
        return create(msg, { status: 400, code: E_MALFORMED });
    },

    //
    // INVALID_TOKEN (dev / client)
    //

    /**
     * @param {number} exp
     * @returns {AuthError}
     */
    TOKEN_EXPIRED: function (exp) {
        //var msg = "The auth token is expired. (exp='" + exp + "')";
        var msg = "token's 'exp' has passed or could not parsed: '" + exp + "'";
        return create(msg, { code: E_INVALID });
    },
    /**
     * @param {number} nbf
     * @returns {AuthError}
     */
    TOKEN_INACTIVE: function (nbf) {
        //var msg = "The auth token is not active yet. (nbf='" + nbf + "')";
        var msg = "token's 'nbf' has not been reached or could not parsed: '" + nbf + "'";
        return create(msg, { code: E_INVALID });
    },
    /** @returns {AuthError} */
    TOKEN_INVALID_SIGNATURE: function () {
        //var msg = "The auth token is not properly signed and could not be verified.";
        var msg = "token signature verification was unsuccessful";
        return create(msg, { code: E_INVALID });
    },
    /** @returns {AuthError} */
    TOKEN_UNKNOWN_SIGNER: function () {
        var msg = "Retrieved a list of keys, but none of them matched the 'kid' (key id) of the token.";
        return create(msg, { code: E_INVALID });
    },
    /**
     * @param {string} id
     * @returns {AuthError}
     */
    JWK_NOT_FOUND: function (id) {
        var msg = "No JWK found by kid or thumbprint '" + id + "'";
        return create(msg, { code: E_INVALID });
    },
    /** @returns {AuthError} */
    OIDC_CONFIG_NOT_FOUND: function () {
        //var msg = "Failed to retrieve OpenID configuration for token issuer";
        var msg = "Failed to retrieve openid configuration";
        return create(msg, { code: E_INVALID });
    },
    /**
     * @param {string} iss
     * @returns {AuthError}
     */
    ISSUER_NOT_TRUSTED: function (iss) {
        var msg = "token was issued by an untrusted issuer: '" + iss + "'";
        return create(msg, { code: E_INVALID });
    },
    /**
     * @param {Array<string>} claimNames
     * @returns {AuthError}
     */
    CLAIMS_MISMATCH: function (claimNames) {
        var msg = "token did not match on one or more authorization claims: '" + claimNames + "'";
        return create(msg, { code: E_INVALID });
    }
};

// for README
if (require.main === module) {
    console.info("| Name | Status | Message (truncated) |");
    console.info("| ---- | ------ | ------------------- |");
    Object.keys(module.exports).forEach(function (k) {
        //@ts-ignore
        var E = module.exports[k];
        var e = E();
        var code = e.code;
        var msg = e.message;
        if ("E_" + k !== e.code) {
            code = k;
            msg = e.details || msg;
        }
        console.info(`| ${code} | ${e.status} | ${msg.slice(0, 45)}... |`);
    });
}
