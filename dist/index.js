"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("crypto");
let nonces = {};
class SapphireAuth {
    constructor(apiKey, apiSecret) {
        this.apiKey = apiKey;
        this.apiSecret = apiSecret;
    }
    static get apiKeyHeaderName() {
        return 'X-Sapphire-API-Key';
    }
    static get timestampHeaderName() {
        return 'X-Sapphire-Timestamp';
    }
    static get signatureHeaderName() {
        return 'X-Sapphire-Signature';
    }
    static get nonceHeaderName() {
        return 'X-Sapphire-Nonce';
    }
    generateSignature(method, url, headers, params) {
        const normalizedHeaderStr = this._generateNormalizedHeaderString(headers);
        const normalizedRequestStr = this._generateNormalizedString(params);
        const token = `${method.toUpperCase()}_${url}_${normalizedHeaderStr}_${normalizedRequestStr}`;
        const hmac = crypto_1.createHmac('SHA256', this.apiSecret);
        return hmac.update(token).digest('base64');
    }
    isExpressRequestValid(req, overrides = {}) {
        const url = `${overrides.protocol || req.protocol}://${overrides.hostname || req.hostname}${req.originalUrl.split('?')[0]}`;
        return this.isMessageValid(req.method, url, req.headers, Object.assign({}, req.query, req.body));
    }
    isMessageValid(method, url, headers, params) {
        const timestamp = headers[SapphireAuth.timestampHeaderName] || headers[SapphireAuth.timestampHeaderName.toLowerCase()];
        if (!timestamp || (parseInt(timestamp, 10) + 1000) <= Date.now()) {
            return false;
        }
        const apiKey = headers[SapphireAuth.apiKeyHeaderName] || headers[SapphireAuth.apiKeyHeaderName.toLowerCase()];
        const nonce = headers[SapphireAuth.nonceHeaderName] || headers[SapphireAuth.nonceHeaderName.toLowerCase()];
        if (nonce) {
            if (!nonces[apiKey]) {
                nonces[apiKey] = new Set();
            }
            const usedNonces = nonces[apiKey];
            if (usedNonces.has(nonce)) {
                return false;
            }
            usedNonces.add(nonce);
        }
        if (!apiKey || apiKey !== this.apiKey) {
            return false;
        }
        const signature = headers[SapphireAuth.signatureHeaderName] || headers[SapphireAuth.signatureHeaderName.toLowerCase()];
        return (signature === this.generateSignature(method, url, headers, params));
    }
    _generateNormalizedHeaderString(headers) {
        const normalizedSignatureHeaderName = SapphireAuth.signatureHeaderName.toLowerCase();
        const sapphireHeaders = {};
        Object.keys(headers).forEach((headerName) => {
            const normalizedHeaderName = headerName.toLowerCase();
            if (normalizedHeaderName.startsWith('x-sapphire-') && normalizedHeaderName !== normalizedSignatureHeaderName) {
                sapphireHeaders[normalizedHeaderName] = headers[headerName];
            }
        });
        return this._generateNormalizedString(sapphireHeaders);
    }
    _generateNormalizedString(obj) {
        let components = [];
        Object.keys(obj).sort().forEach((paramName) => {
            let value = obj[paramName];
            if (typeof value === 'object') {
                value = this._generateNormalizedString(value);
            }
            components.push(`${encodeURIComponent(paramName)}=${encodeURIComponent(value)}`);
        });
        return components.join('&');
    }
    static __resetNonces() {
        nonces = {};
    }
}
exports.default = SapphireAuth;
//# sourceMappingURL=index.js.map