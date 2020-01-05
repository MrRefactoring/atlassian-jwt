import * as assert from 'assert';
import moment from 'moment';
import qs from 'qs';
import * as jwt from '../index';
import { Request } from 'express';

describe('JWT', function () {
    const issuer = 'com.atlassian.test';
    const sharedSecret = 'a-s3cr3t-k3y';

    // https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
    const supportedAlgs = ['HS256', 'HS384', 'HS512'];
    const someNonSupportedAlgs = [
        'none',
        'RS256', 'RS384', 'RS512',
        'ES256', 'ES384', 'ES512',
        'PS256', 'PS384'
    ];

    // Online token generator: https://jwt.io
    const someNonSupportedTokens: { [key: string]: string } = {
        'none': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.',
        'RS256': 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA',
        'RS384': 'eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.D4kXa3UspFjRA9ys5tsD4YDyxxam3l_XnOb3hMEdPDTfSLRHPv4HPwxvin-pIkEmfJshXPSK7O4zqSXWAXFO52X-upJjFc_gpGDswctNWpOJeXe1xBgJ--VuGDzUQCqkr9UBpN-Q7TE5u9cgIVisekSFSH5Ax6aXQC9vCO5LooNFx_WnbTLNZz7FUia9vyJ544kLB7UcacL-_idgRNIWPdd_d1vvnNGkknIMarRjCsjAEf6p5JGhYZ8_C18g-9DsfokfUfSpKgBR23R8v8ZAAmPPPiJ6MZXkefqE7p3jRbA--58z5TlHmH9nTB1DYE2872RYvyzG3LoQ-2s93VaVuw',
        'RS512': 'eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.JlX3gXGyClTBFciHhknWrjo7SKqyJ5iBO0n-3S2_I7cIgfaZAeRDJ3SQEbaPxVC7X8aqGCOM-pQOjZPKUJN8DMFrlHTOdqMs0TwQ2PRBmVAxXTSOZOoEhD4ZNCHohYoyfoDhJDP4Qye_FCqu6POJzg0Jcun4d3KW04QTiGxv2PkYqmB7nHxYuJdnqE3704hIS56pc_8q6AW0WIT0W-nIvwzaSbtBU9RgaC7ZpBD2LiNE265UBIFraMDF8IAFw9itZSUCTKg1Q-q27NwwBZNGYStMdIBDor2Bsq5ge51EkWajzZ7ALisVp-bskzUsqUf77ejqX_CBAqkNdH1Zebn93A',
        'ES256': 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA',
        'ES384': 'eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6ImlUcVhYSTB6YkFuSkNLRGFvYmZoa00xZi02ck1TcFRmeVpNUnBfMnRLSTgifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.cJOP_w-hBqnyTsBm3T6lOE5WpcHaAkLuQGAs1QO-lg2eWs8yyGW8p9WagGjxgvx7h9X72H7pXmXqej3GdlVbFmhuzj45A9SXDOAHZ7bJXwM1VidcPi7ZcrsMSCtP1hiN',
        'ES512': 'eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6InhaRGZacHJ5NFA5dlpQWnlHMmZOQlJqLTdMejVvbVZkbTd0SG9DZ1NOZlkifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.AP_CIMClixc5-BFflmjyh_bRrkloEvwzn8IaWJFfMz13X76PGWF0XFuhjJUjp7EYnSAgtjJ-7iJG4IP7w3zGTBk_AUdmvRCiWp5YAe8S_Hcs8e3gkeYoOxiXFZlSSAx0GfwW1cZ0r67mwGtso1I3VXGkSjH5J0Rk6809bn25GoGRjOPu',
        'PS256': 'eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.hZnl5amPk_I3tb4O-Otci_5XZdVWhPlFyVRvcqSwnDo_srcysDvhhKOD01DigPK1lJvTSTolyUgKGtpLqMfRDXQlekRsF4XhAjYZTmcynf-C-6wO5EI4wYewLNKFGGJzHAknMgotJFjDi_NCVSjHsW3a10nTao1lB82FRS305T226Q0VqNVJVWhE4G0JQvi2TssRtCxYTqzXVt22iDKkXeZJARZ1paXHGV5Kd1CljcZtkNZYIGcwnj65gvuCwohbkIxAnhZMJXCLaVvHqv9l-AAUV7esZvkQR1IpwBAiDQJh4qxPjFGylyXrHMqh5NlT_pWL2ZoULWTg_TJjMO9TuQ',
        'PS384': 'eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.MqF1AKsJkijKnfqEI3VA1OnzAL2S4eIpAuievMgD3tEFyFMU67gCbg-fxsc5dLrxNwdZEXs9h0kkicJZ70mp6p5vdv-j2ycDKBWg05Un4OhEl7lYcdIsCsB8QUPmstF-lQWnNqnq3wra1GynJrOXDL27qIaJnnQKlXuayFntBF0j-82jpuVdMaSXvk3OGaOM-7rCRsBcSPmocaAO-uWJEGPw_OWVaC5RRdWDroPi4YL4lTkDEC-KEvVkqCnFm_40C-T_siXquh5FVbpJjb3W2_YvcqfDRj44TsRrpVhk6ohsHMNeUad_cxnFnpolIKnaXq_COv35e9EgeQIPAbgIeg'
    };

    const jwtPayload = {
        'sub': 'admin',
        'iss': issuer,
        'iat': moment().utc().unix(),
        'exp': moment().utc().add(10, 'minutes').unix()
    };

    describe('Algorithms', function() {
        supportedAlgs.forEach(alg => {
            it(`"encode" should support ${alg}`, function() {
                // No exception should be thrown
                jwt.encode(jwtPayload, sharedSecret, alg as jwt.Algorithm);
            });
        });

        someNonSupportedAlgs.forEach(alg => {
            it(`"encode" should not support ${alg}`, function() {
                const encodeFunc = () => jwt.encode(jwtPayload, sharedSecret, alg as jwt.Algorithm);
                assert.throws(encodeFunc, Error(`Algorithm "${alg}" is not supported`));
            });
        });

        supportedAlgs.forEach(alg => {
            it(`"decode" should support ${alg}`, function() {
            // No exception should be thrown
                const token = jwt.encode(jwtPayload, sharedSecret, alg as jwt.Algorithm);
                jwt.decode(token, sharedSecret);
            });
        });

        someNonSupportedAlgs.forEach(alg => {
            it(`"decode" should not support ${alg}`, function() {
                const token = someNonSupportedTokens[alg];
                const key = 'ignored'; // Algorithm should be checked first, so key is not important
                const decodeFunc = () => jwt.decode(token, key);
                assert.throws(decodeFunc, Error(`Algorithm "${alg}" is not supported`));
            });
        });
    });

    it('should correctly create canonical request', function (done) {
        const req = jwt.fromExpressRequest({
            method: 'get',
            originalUrl: '/path/to/service',
            query: qs.parse('zee_last=param&repeated=parameter 1&first=param&repeated=parameter 2&repeated=Parameter 2')
        } as Request);
        const expectedCanonical = "GET&/path/to/service&first=param&repeated=Parameter%202,parameter%201,parameter%202&zee_last=param";

        const canonical = jwt.createCanonicalRequest(req);
        assert.equal(canonical, expectedCanonical);
        done();
    });

    it('should correctly create canonical request ignoring app baseUrl', function (done) {
        const req = jwt.fromExpressRequest({
            method: 'get',
            originalUrl: '/base/path/to/service',
            query: qs.parse('zee_last=param&repeated=parameter 1&first=param&repeated=parameter 2&repeated=Parameter 2')
        } as Request);
        const expectedCanonical = "GET&/path/to/service&first=param&repeated=Parameter%202,parameter%201,parameter%202&zee_last=param";

        const canonical = jwt.createCanonicalRequest(req, false, 'https://bitbucket.org/base');
        assert.equal(canonical, expectedCanonical);
        done();
    });

    it('should correctly create canonical request ignoring jwt param', function (done) {
        const req = jwt.fromExpressRequest({
            method: 'get',
            originalUrl: '/hello-world',
            query: qs.parse('lic=none&tz=Australia%2FSydney&cp=%2Fjira&user_key=&loc=en-US&user_id=&jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEzODY4OTkxMzEsImlzcyI6ImppcmE6MTU0ODk1OTUiLCJxc2giOiI4MDYzZmY0Y2ExZTQxZGY3YmM5MGM4YWI2ZDBmNjIwN2Q0OTFjZjZkYWQ3YzY2ZWE3OTdiNDYxNGI3MTkyMmU5IiwiaWF0IjoxMzg2ODk4OTUxfQ.uKqU9dTB6gKwG6jQCuXYAiMNdfNRw98Hw_IWuA5MaMo&xdm_e=http%3A%2F%2Fstorm%3A2990&xdm_c=channel-servlet-hello-world&xdm_p=1')
        } as Request);
        const expectedCanonical = "GET&/hello-world&cp=%2Fjira&lic=none&loc=en-US&tz=Australia%2FSydney&user_id=&user_key=&xdm_c=channel-servlet-hello-world&xdm_e=http%3A%2F%2Fstorm%3A2990&xdm_p=1";

        const canonical = jwt.createCanonicalRequest(req, false, '');
        assert.equal(canonical, expectedCanonical);
        done();
    });

    it('should correctly create canonical request with valueless parameters', function (done) {
        const req = jwt.fromExpressRequest({
            method: 'get',
            originalUrl: '/hello-world',
            query: qs.parse('a&b=foo&c')
        } as Request);
        const expectedCanonical = "GET&/hello-world&a=&b=foo&c=";

        const canonical = jwt.createCanonicalRequest(req, false, '');
        assert.equal(canonical, expectedCanonical);
        done();
    });

    it('should correctly create canonical request with context in path', function (done) {
        const req = jwt.fromExpressRequest({
            method: 'post',
            originalUrl: '/jira/rest/api/2/project/jira&a=b&c=d',
            query: qs.parse('x=y'),
            body: ''
        } as Request);

        assert.equal(jwt.createCanonicalRequest(req, false, '/jira'), 'POST&/rest/api/2/project/jira%26a=b%26c=d&x=y');
        done();
    });

    // Coverage for https://bitbucket.org/atlassian/atlassian-jwt-js/issues/6
    it('should generate a qsh for the entire path when used in middleware', function(done) {
        const req = jwt.fromExpressRequest({
            method: 'get',
            path: '/project',
            originalUrl: '/jira/rest/api/2/project/jira',
            query: qs.parse('x=y'),
        } as Request);

        assert.equal(jwt.createCanonicalRequest(req, false, '/jira'), 'GET&/rest/api/2/project/jira&x=y');
        done();
    });

    // If the separator is not URL encoded then the following URLs have the same query-string-hash:
    //   https://djtest9.jira-dev.com/rest/api/2/project&a=b?x=y
    //   https://djtest9.jira-dev.com/rest/api/2/project?a=b&x=y
    describe('paths containing "&" characters should not have spoof-able qsh claims', function () {
        it('requests that differ by ampersands in the path versus query-string do not have the same canonical request string', function (done) {
            const req1 = jwt.fromExpressRequest({
                method: 'post',
                originalUrl: '/rest/api/2/project&a=b',
                query: qs.parse('x=y'),
                body: ''
            } as Request);
            const req2 = jwt.fromExpressRequest({
                method: 'post',
                originalUrl: '/rest/api/2/project',
                query: qs.parse('a=b&x=y'),
                body: ''
            } as Request);

            assert.notEqual(jwt.createCanonicalRequest(req1, false, ''), jwt.createCanonicalRequest(req2, false, ''));
            done();
        });

        it('an ampersand in the path is url-encoded', function (done) {
            const req = jwt.fromExpressRequest({
                method: 'post',
                originalUrl: '/rest/api/2/project&a=b',
                query: qs.parse('x=y'),
                body: ''
            } as Request);

            assert.equal(jwt.createCanonicalRequest(req, false, ''), 'POST&/rest/api/2/project%26a=b&x=y');
            done();
        });

        it('multiple ampersands in the path are encoded', function (done) {
            const req = jwt.fromExpressRequest({
                method: 'post',
                originalUrl: '/rest/api/2/project&a=b&c=d',
                query: qs.parse('x=y'),
                body: ''
            } as Request);

            assert.equal(jwt.createCanonicalRequest(req, false, ''), 'POST&/rest/api/2/project%26a=b%26c=d&x=y');
            done();
        });
    });

    describe('qsh', function () {
        it('should correctly create qsh without query string', function (done) {
            const req = jwt.fromExpressRequest({
                method: 'get',
                originalUrl: '/path'
            } as Request);
            const expectedHash = "799be84a7fa35570087163c0cd9af3abff7ac05c2c12ba0bb1d7eebc984b3ac2";

            const qsh = jwt.createQueryStringHash(req);
            assert.equal(qsh, expectedHash);
            done();
        });

        it('should correctly create qsh without path or query string', function (done) {
            const req = jwt.fromExpressRequest({
                method: 'get'
            } as Request);
            const expectedHash = "c88caad15a1c1a900b8ac08aa9686f4e8184539bea1deda36e2f649430df3239";

            const qsh = jwt.createQueryStringHash(req);
            assert.equal(qsh, expectedHash);
            done();
        });

        it('should correctly create qsh with empty path and no query string', function (done) {
            const req = jwt.fromExpressRequest({
                method: 'get',
                originalUrl: '/'
            } as Request);
            const expectedHash = "c88caad15a1c1a900b8ac08aa9686f4e8184539bea1deda36e2f649430df3239";

            const qsh = jwt.createQueryStringHash(req);
            assert.equal(qsh, expectedHash);
            done();
        });

        it('should correctly create qsh with query string', function (done) {
            const req = jwt.fromExpressRequest({
                method: 'get',
                originalUrl: '/hello-world',
                query: qs.parse('lic=none&tz=Australia%2FSydney&cp=%2Fjira&user_key=&loc=en-US&user_id=&jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEzODY5MTEzNTYsImlzcyI6ImppcmE6MTU0ODk1OTUiLCJxc2giOiI4MDYzZmY0Y2ExZTQxZGY3YmM5MGM4YWI2ZDBmNjIwN2Q0OTFjZjZkYWQ3YzY2ZWE3OTdiNDYxNGI3MTkyMmU5IiwiaWF0IjoxMzg2OTExMTc2fQ.rAsxpHv0EvpXkhjnZnSV14EXJgDx3KSQjgYRjfKnFt8&xdm_e=http%3A%2F%2Fstorm%3A2990&xdm_c=channel-servlet-hello-world&xdm_p=1')
            } as Request);
            const expectedHash = "8063ff4ca1e41df7bc90c8ab6d0f6207d491cf6dad7c66ea797b4614b71922e9";

            const qsh = jwt.createQueryStringHash(req);
            assert.equal(qsh, expectedHash);
            done();
        });

        // apache http client likes to do this
        it('should correctly create qsh with POST body query string', function (done) {
            const req = jwt.fromExpressRequest({
                method: 'post',
                originalUrl: '/hello-world',
                query: {},
                body: qs.parse('lic=none&tz=Australia%2FSydney&cp=%2Fjira&user_key=&loc=en-US&user_id=&jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEzODY5MTEzNTYsImlzcyI6ImppcmE6MTU0ODk1OTUiLCJxc2giOiI4MDYzZmY0Y2ExZTQxZGY3YmM5MGM4YWI2ZDBmNjIwN2Q0OTFjZjZkYWQ3YzY2ZWE3OTdiNDYxNGI3MTkyMmU5IiwiaWF0IjoxMzg2OTExMTc2fQ.rAsxpHv0EvpXkhjnZnSV14EXJgDx3KSQjgYRjfKnFt8&xdm_e=http%3A%2F%2Fstorm%3A2990&xdm_c=channel-servlet-hello-world&xdm_p=1')
            } as Request);
            const expectedHash = "d7e7f00660965fc15745b2c423a89b85d0853c4463faca362e0371d008eb0927";

            const qsh = jwt.createQueryStringHash(req, true);
            assert.equal(qsh, expectedHash);
            done();
        });

        // Apache http client likes to do this
        it('should not correctly create qsh with POST body query string if not instructed to', function (done) {
            const req = jwt.fromExpressRequest({
                method: 'post',
                originalUrl: '/hello-world',
                query: {},
                body: qs.parse('lic=none&tz=Australia%2FSydney&cp=%2Fjira&user_key=&loc=en-US&user_id=&jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEzODY5MTEzNTYsImlzcyI6ImppcmE6MTU0ODk1OTUiLCJxc2giOiI4MDYzZmY0Y2ExZTQxZGY3YmM5MGM4YWI2ZDBmNjIwN2Q0OTFjZjZkYWQ3YzY2ZWE3OTdiNDYxNGI3MTkyMmU5IiwiaWF0IjoxMzg2OTExMTc2fQ.rAsxpHv0EvpXkhjnZnSV14EXJgDx3KSQjgYRjfKnFt8&xdm_e=http%3A%2F%2Fstorm%3A2990&xdm_c=channel-servlet-hello-world&xdm_p=1')
            } as Request);
            const expectedHash = "6f95f3738e1b037a3bebbe0ad237d80fdbc1d5ae452e98ce03a9c004c178ebb4";

            const qsh = jwt.createQueryStringHash(req, false);
            assert.equal(qsh, expectedHash);
            done();
        });
    });
});
