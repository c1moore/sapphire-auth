/* eslint-disable no-undef */
const Sinon = require('sinon');

require('should');

const SapphireAuth = require('../dist').default;

describe('SapphireAuth', () => {
  const apiKey = 'abcdefghijklmnopqrstuvwxyz';
  const apiSecret = '1234567989-abcd';

  let auth;

  beforeEach(() => {
    auth = new SapphireAuth(apiKey, apiSecret);
  });

  describe('generateSignature()', () => {
    it('should generate a valid signature with a flat params object', () => {
      const signature = auth.generateSignature('GET', 'https://callrestrictions.com/api/v1/allowable-hours',
        {
          [SapphireAuth.apiKeyHeaderName]:    apiKey,
          [SapphireAuth.timestampHeaderName]: 1564350579593,
          [SapphireAuth.nonceHeaderName]:     'abcdefgh',
          'Content-Type':                     'application/json',
        },
        {
          areaCode: '863',
          isB2B:    true,
        }
      );

      signature.should.equal('3LK+N7E5fgxN4tHDeSWk1vH400MwIt5+PDekcF6+YYA=');
    });

    it('should generate a valid signature if any of the values include URI unsafe characters', () => {
      const signature = auth.generateSignature('GET', 'https://callrestrictions.com/api/v1/allowable-hours',
        {
          [SapphireAuth.apiKeyHeaderName]:    apiKey,
          [SapphireAuth.timestampHeaderName]: 1564350579593,
          [SapphireAuth.nonceHeaderName]:     'abcd/efgh',
          'Content-Type':                     'application/json',
        },
        {
          areaCode: '863',
          isB2B:    true,
        }
      );

      signature.should.equal('5XecuZbJ2FX4X64LAHnmClDNOUc9PVvddHGTGA/VYLU=');
    });

    it('should generate a valid signature with nested param objects', () => {
      const signature = auth.generateSignature('POST', 'https://callrestrictions.com/api/v1/allowable-hours',
        {
          [SapphireAuth.apiKeyHeaderName]:    apiKey,
          [SapphireAuth.timestampHeaderName]: 1564350579593,
          [SapphireAuth.nonceHeaderName]:     'abcd/efgh',
          'Content-Type':                     'application/json',
        },
        {
          test: {
            testName: 'test3',
            testPass: true,
            nested0:  {
              1: '2',
            },
            nested: {
              a: 'b',
              c: 'd',
            },
          },
          areaCode: '863',
          isB2B:    true,
        }
      );

      signature.should.equal('oZSPpDI/MVCPb1imZyp5N+9H+FFG8+Umkx2P3nj0pwo=');
    });
  });

  describe('isExpressRequestValid()', () => {
    let req;
    let sandbox;

    beforeEach(() => {
      req = {
        protocol:    'https',
        hostname:    'c1moore.codes',
        originalUrl: '/api/test?something=true&somethingElse=false',
        method:      'POST',
        headers:     {},
        query:       {
          something:     true,
          somethingElse: false,
        },
        body: {
          test: true,
        },
      };
    });

    beforeEach(() => {
      sandbox = Sinon.createSandbox();
      sandbox.stub(SapphireAuth.prototype, 'isMessageValid');

      auth = new SapphireAuth(apiKey, apiSecret);
    });

    afterEach(() => {
      sandbox.restore();
    })

    it('should use the appropriate values from the Express object', () => {
      auth.isExpressRequestValid(req);

      Sinon.assert.calledOnce(SapphireAuth.prototype.isMessageValid);
      Sinon.assert.calledWith(
        SapphireAuth.prototype.isMessageValid,
        req.method,
        `${req.protocol}://${req.hostname}${req.originalUrl.split('?')[0]}`,
        req.headers,
        Sinon.match
          .has('something', true)
          .and(Sinon.match.has('somethingElse', false))
          .and(Sinon.match.has('test', true))
      );
    });

    it('should use the protocol override if specified', () => {
      const protocol = 'fake';

      auth.isExpressRequestValid(req, { protocol });

      Sinon.assert.calledOnce(SapphireAuth.prototype.isMessageValid);
      Sinon.assert.calledWith(SapphireAuth.prototype.isMessageValid, Sinon.match.any, `${protocol}://${req.hostname}${req.originalUrl.split('?')[0]}`);
    });

    it('should use the hostname override if specified', () => {
      const hostname = `subdomain.${req.hostname}`;

      auth.isExpressRequestValid(req, { hostname });

      Sinon.assert.calledOnce(SapphireAuth.prototype.isMessageValid);
      Sinon.assert.calledWith(SapphireAuth.prototype.isMessageValid, Sinon.match.any, `${req.protocol}://${hostname}${req.originalUrl.split('?')[0]}`);
    });
  });

  describe('isMessageValid()', () => {
    let timer = null;

    beforeEach(() => {
      timer = Sinon.useFakeTimers();
    });

    afterEach(() => {
      SapphireAuth.__resetNonces();

      timer.restore();
    });

    it('should validate a valid signature', () => {
      timer.setSystemTime(1564350580093);

      const isValid = auth.isMessageValid('POST', 'https://callrestrictions.com/api/v1/allowable-hours',
        {
          [SapphireAuth.apiKeyHeaderName]:    apiKey,
          [SapphireAuth.timestampHeaderName]: 1564350579593,
          [SapphireAuth.nonceHeaderName]:     'abcd/efgh',
          'Content-Type':                     'application/json',
          [SapphireAuth.signatureHeaderName]: 'oZSPpDI/MVCPb1imZyp5N+9H+FFG8+Umkx2P3nj0pwo=',
        },
        {
          test: {
            testName: 'test3',
            testPass: true,
            nested0:  {
              1: '2',
            },
            nested: {
              a: 'b',
              c: 'd',
            },
          },
          areaCode: '863',
          isB2B:    true,
        }
      );

      isValid.should.be.true();
    });

    it('should not validate an invalid signature', () => {
      timer.setSystemTime(1564350580093);

      const isValid = auth.isMessageValid('POST', 'https://callrestrictions.com/api/v1/allowable-hours',
        {
          [SapphireAuth.apiKeyHeaderName]:    apiKey,
          [SapphireAuth.timestampHeaderName]: 1564350579593,
          [SapphireAuth.nonceHeaderName]:     'abcdefgh',
          'Content-Type':                     'application/json',
          [SapphireAuth.signatureHeaderName]: 'this_is_invalid-oZSPpDI/MVCPb1imZyp5N+9H+FFG8+Umkx2P3nj0pwo==',
        },
        {
          test: {
            testName: 'test3',
            testPass: true,
            nested0:  {
              1: '2',
            },
            nested: {
              a: 'b',
              c: 'd',
            },
          },
          areaCode: '863',
          isB2B:    true,
        }
      );

      isValid.should.be.false();
    });

    it('should not validate a request with a timestamp from over 1 second ago', () => {
      timer.setSystemTime(1564350580594);

      const isValid = auth.isMessageValid('POST', 'https://callrestrictions.com/api/v1/allowable-hours',
        {
          [SapphireAuth.apiKeyHeaderName]:    apiKey,
          [SapphireAuth.timestampHeaderName]: 1564350579593,
          [SapphireAuth.nonceHeaderName]:     'abcd/efgh',
          'Content-Type':                     'application/json',
          [SapphireAuth.signatureHeaderName]: 'oZSPpDI/MVCPb1imZyp5N+9H+FFG8+Umkx2P3nj0pwo=',
        },
        {
          test: {
            testName: 'test3',
            testPass: true,
            nested0:  {
              1: '2',
            },
            nested: {
              a: 'b',
              c: 'd',
            },
          },
          areaCode: '863',
          isB2B:    true,
        }
      );

      isValid.should.be.false();
    });

    it('should not validate a request with a nonce that has already been seen', () => {
      timer.setSystemTime(1564350580093);

      auth.isMessageValid('POST', 'https://callrestrictions.com/api/v1/allowable-hours',
        {
          [SapphireAuth.apiKeyHeaderName]:    apiKey,
          [SapphireAuth.timestampHeaderName]: 1564350579593,
          [SapphireAuth.nonceHeaderName]:     'abcd/efgh',
          'Content-Type':                     'application/json',
          [SapphireAuth.signatureHeaderName]: 'oZSPpDI/MVCPb1imZyp5N+9H+FFG8+Umkx2P3nj0pwo=',
        },
        {
          test: {
            testName: 'test3',
            testPass: true,
            nested0:  {
              1: '2',
            },
            nested: {
              a: 'b',
              c: 'd',
            },
          },
          areaCode: '863',
          isB2B:    true,
        }
      ).should.be.true();

      auth.isMessageValid('POST', 'https://callrestrictions.com/api/v1/allowable-hours',
        {
          [SapphireAuth.apiKeyHeaderName]:    apiKey,
          [SapphireAuth.timestampHeaderName]: 1564350579593,
          [SapphireAuth.nonceHeaderName]:     'abcd/efgh',
          'Content-Type':                     'application/json',
          [SapphireAuth.signatureHeaderName]: 'oZSPpDI/MVCPb1imZyp5N+9H+FFG8+Umkx2P3nj0pwo=',
        },
        {
          test: {
            testName: 'test3',
            testPass: true,
            nested0:  {
              1: '2',
            },
            nested: {
              a: 'b',
              c: 'd',
            },
          },
          areaCode: '863',
          isB2B:    true,
        }
      ).should.be.false();
    });

    it('should validate a request without a nonce', () => {
      const signature = auth.generateSignature('GET', 'https://callrestrictions.com/api/v1/allowable-hours',
        {
          [SapphireAuth.apiKeyHeaderName]:    apiKey,
          [SapphireAuth.timestampHeaderName]: 1564350579593,
          'Content-Type':                     'application/json',
        },
        {
          areaCode: '863',
          isB2B:    true,
        }
      );

      auth.isMessageValid('GET', 'https://callrestrictions.com/api/v1/allowable-hours',
        {
          [SapphireAuth.apiKeyHeaderName]:    apiKey,
          [SapphireAuth.timestampHeaderName]: 1564350579593,
          'Content-Type':                     'application/json',
          [SapphireAuth.signatureHeaderName]: signature,
        },
        {
          areaCode: '863',
          isB2B:    true,
        }
      ).should.be.true();

      auth.isMessageValid('GET', 'https://callrestrictions.com/api/v1/allowable-hours',
        {
          [SapphireAuth.apiKeyHeaderName]:    apiKey,
          [SapphireAuth.timestampHeaderName]: 1564350579593,
          'Content-Type':                     'application/json',
          [SapphireAuth.signatureHeaderName]: signature,
        },
        {
          areaCode: '863',
          isB2B:    true,
        }
      ).should.be.true();
    });

    it('should not validate a request without an API key', () => {
      timer.setSystemTime(1564350580093);

      const isValid = auth.isMessageValid('POST', 'https://callrestrictions.com/api/v1/allowable-hours',
        {
          [SapphireAuth.timestampHeaderName]: 1564350579593,
          [SapphireAuth.nonceHeaderName]:     'abcd/efgh',
          'Content-Type':                     'application/json',
          [SapphireAuth.signatureHeaderName]: 'oZSPpDI/MVCPb1imZyp5N+9H+FFG8+Umkx2P3nj0pwo=',
        },
        {
          test: {
            testName: 'test3',
            testPass: true,
            nested0:  {
              1: '2',
            },
            nested: {
              a: 'b',
              c: 'd',
            },
          },
          areaCode: '863',
          isB2B:    true,
        }
      );

      isValid.should.be.false();
    });
  });
});