import { Request } from 'express';
export default class SapphireAuth {
    private apiKey;
    private apiSecret;
    constructor(apiKey: string, apiSecret: string);
    static readonly apiKeyHeaderName: string;
    static readonly timestampHeaderName: string;
    static readonly signatureHeaderName: string;
    static readonly nonceHeaderName: string;
    generateSignature(method: string, url: string, headers: {
        [headerName: string]: string | string[] | undefined;
    }, params: {
        [paramName: string]: any;
    }): string;
    isExpressRequestValid(req: Request, overrides?: {
        protocol?: string;
        hostname?: string;
    }): boolean;
    isMessageValid(method: string, url: string, headers: {
        [headerName: string]: string | string[] | undefined;
    }, params: {
        [paramName: string]: any;
    }): boolean;
    private _generateNormalizedHeaderString;
    private _generateNormalizedString;
    protected static __resetNonces(): void;
}
