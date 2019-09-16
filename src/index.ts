import { createHmac } from 'crypto';
import { Request } from 'express';

let nonces: { [ apiKey: string ]: Set<string> } = {};

export default class SapphireAuth {
  private apiKey: string;
  private apiSecret: string;

  constructor(apiKey: string, apiSecret: string) {
    this.apiKey = apiKey;
    this.apiSecret = apiSecret;
  }

  /**
   * The name of the header that contains the API key.  This header is required for all
   * requests.
   */
  static get apiKeyHeaderName(): string {
    return 'X-Sapphire-API-Key';
  }

  /**
   * The name of the header that contains the timestamp for when the request was sent.
   * This header is required for all requests.  The timestamp must be in milliseconds
   * since the Unix epoch.  The request must be received within 1000ms (1 second) of when
   * the request was sent.
   */
  static get timestampHeaderName(): string {
    return 'X-Sapphire-Timestamp';
  }

  /**
   * The name of the header that contains the Sapphire signature.  This header is required
   * for all requests.
   */
  static get signatureHeaderName(): string {
    return 'X-Sapphire-Signature';
  }

  /**
   * The name of the header that contains a unique token for each request.  This token
   * can be used to help avoid replay attacks.  While not required, it is strongly
   * recommended.
   */
  static get nonceHeaderName(): string {
    return 'X-Sapphire-Nonce';
  }

  /**
   * Generates the Sapphire signature that should be added to the headers in a request to
   * Sapphire.
   *
   * @param {string} method the HTTP method used for this request
   * @param {string} url the URL of the resource being requested.  This does not include
   * the query param string
   * @param {{ [ headerName: string ]: string }} headers the headers being sent with the
   * request
   * @param {{ [ paramName: string ]: any }} params the parameters included in the
   * request.  This includes query string params, URL encoded parameters (as an object),
   * or a JSON body
   *
   * @returns {string} the signature
   */
  generateSignature(method: string, url: string, headers: { [ headerName: string ]: string | string[] | undefined }, params: { [ paramName: string ]: any }): string {
    const normalizedHeaderStr = this._generateNormalizedHeaderString(headers);
    const normalizedRequestStr = this._generateNormalizedString(params);

    const token = `${method.toUpperCase()}_${url}_${normalizedHeaderStr}_${normalizedRequestStr}`;

    const hmac = createHmac('SHA256', this.apiSecret);

    return hmac.update(token).digest('base64');
  }

  /**
   * A shorthand for `isMessageValid()` for Express.js apps.
   *
   * @see SapphireAuth#isMessageValid
   *
   * @param {Request} req the Express.js request object
   * @param {[object]} overrides any overrides that should be applied to the request
   * object.  This is useful, for example, if you are behind another application that
   * redirects traffic to your Express instance.
   * @param {[string]} overrides.protocol the protocol to use when generating the
   * signature
   * @param {[string]} overrides.hostname the hostname to use when generating the
   * signature
   */
  isExpressRequestValid(req: Request, overrides: { protocol?: string, hostname?: string } = {}): boolean {
    const url = `${overrides.protocol || req.protocol}://${overrides.hostname || req.hostname}${req.originalUrl.split('?')[0]}`;

    return this.isMessageValid(req.method, url, req.headers, { ...req.query, ...req.body });
  }

  /**
   * Validates an HTTP request or response.
   *
   * @param {string} method the HTTP method used for this request
   * @param {string} url the URL of the resource being requested.  This does not include
   * the query param string
   * @param {{ [ headerName: string ]: string }} headers the headers being sent with the
   * request
   * @param {{ [ paramName: string ]: any }} params the parameters included in the
   * request.  This includes query string params, URL encoded parameters (as an object),
   * or a JSON body
   *
   * @returns {boolean} true if the message is valid; false otherwise
   */
  isMessageValid(method: string, url: string, headers: { [ headerName: string ]: string | string[] | undefined }, params: { [ paramName: string ]: any }): boolean {
    const timestamp = <string> headers[SapphireAuth.timestampHeaderName] || <string> headers[SapphireAuth.timestampHeaderName.toLowerCase()];
    if (!timestamp || (parseInt(timestamp, 10) + 1000) <= Date.now()) {
      return false;
    }

    const apiKey = <string> headers[SapphireAuth.apiKeyHeaderName] || <string> headers[SapphireAuth.apiKeyHeaderName.toLowerCase()];

    const nonce = <string> headers[SapphireAuth.nonceHeaderName] || <string> headers[SapphireAuth.nonceHeaderName.toLowerCase()];
    if (nonce) {
      if (!nonces[apiKey]) {
        nonces[apiKey] = new Set<string>();
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

  private _generateNormalizedHeaderString(headers: { [ headerName: string ]: string | string[] | undefined }): string {
    const normalizedSignatureHeaderName = SapphireAuth.signatureHeaderName.toLowerCase();

    const sapphireHeaders: { [ headerName: string ]: string } = {};

    Object.keys(headers).forEach((headerName: string): void => {
      const normalizedHeaderName = headerName.toLowerCase();

      if (normalizedHeaderName.startsWith('x-sapphire-') && normalizedHeaderName !== normalizedSignatureHeaderName) {
        sapphireHeaders[normalizedHeaderName] = <string> headers[headerName];
      }
    });

    return this._generateNormalizedString(sapphireHeaders);
  }

  private _generateNormalizedString(obj: { [ paramName: string ]: any }): string {
    let components: string[] = [];

    Object.keys(obj).sort().forEach((paramName: string): void => {
      let value = obj[paramName];

      if (typeof value === 'object') {
        value = this._generateNormalizedString(value);
      }

      components.push(`${encodeURIComponent(paramName)}=${encodeURIComponent(value)}`);
    });

    return components.join('&');
  }

  protected static __resetNonces(): void {
    nonces = {};
  }
}