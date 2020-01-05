import * as jwt from '../index';
import * as assert from 'assert';

describe('Request Parsing - fromMethodAndUrl', function () {
    it('With no path or params', done => {
        const req = jwt.fromMethodAndUrl('get', 'https://example.com');
        assert.equal(req.method, 'get');
        assert.equal(req.pathname, '/');
        assert.equal(Object.keys(req.query || {}).length, 0);
        assert.equal(Object.keys(req.body || {}).length, 0);
        done();
    });

    it('With no params', done => {
        const req = jwt.fromMethodAndUrl('get', 'https://example.com/path/to/resource');
        assert.equal(req.method, 'get');
        assert.equal(req.pathname, '/path/to/resource');
        assert.equal(Object.keys(req.query || {}).length, 0);
        assert.equal(Object.keys(req.body || {}).length, 0);
        done();
    });

    it('With no params or baseUrl', done => {
        const req = jwt.fromMethodAndUrl('get', '/path/to/resource');
        assert.equal(req.method, 'get');
        assert.equal(req.pathname, '/path/to/resource');
        assert.equal(Object.keys(req.query || {}).length, 0);
        assert.equal(Object.keys(req.body || {}).length, 0);
        done();
    });

    it('With simple params', done => {
        const req = jwt.fromMethodAndUrl('get', 'https://example.com/path/to/resource?a=123&b=265');
        assert.equal(req.method, 'get');
        assert.equal(req.pathname, '/path/to/resource');

        const query = req.query || {};
        assert.equal(Object.keys(query).length, 2);
        assert.equal(query.a, 123);
        assert.equal(query.b, 265);

        assert.equal(Object.keys(req.body || {}).length, 0);
        done();
    });

    // For complex types, this is different behaviour to Express.js. So this is unsupported.
    it('With complex params the parsing is different', done => {
        const req = jwt.fromMethodAndUrl('get', 'https://example.com/path/to/resource?a[type]=123&b=265&a[boop]=hello');
        assert.equal(req.method, 'get');
        assert.equal(req.pathname, '/path/to/resource');

        const query = req.query || {};
        assert.equal(Object.keys(query).length, 3);
        assert.equal(query['a[type]'], 123);
        assert.equal(query['a[boop]'], 'hello');
        assert.equal(query.b, 265);

        assert.equal(Object.keys(req.body || {}).length, 0);

        done();
    });
});

describe('Request Parsing - fromMethodAndPathAndBody', function () {
    it('With no path or params', done => {
        const req = jwt.fromMethodAndPathAndBody('post', 'https://example.com', {});
        assert.equal(req.method, 'post');
        assert.equal(req.pathname, '/');
        assert.equal(Object.keys(req.query || {}).length, 0);
        assert.equal(Object.keys(req.body || {}).length, 0);
        done();
    });

    it('With no params', done => {
        const req = jwt.fromMethodAndPathAndBody('put', 'https://example.com/path/to/resource', {});
        assert.equal(req.method, 'put');
        assert.equal(req.pathname, '/path/to/resource');
        assert.equal(Object.keys(req.query || {}).length, 0);
        assert.equal(Object.keys(req.body || {}).length, 0);
        done();
    });

    it('With no params or baseUrl', done => {
        const req = jwt.fromMethodAndPathAndBody('post', '/path/to/resource', {});
        assert.equal(req.method, 'post');
        assert.equal(req.pathname, '/path/to/resource');
        assert.equal(Object.keys(req.query || {}).length, 0);
        assert.equal(Object.keys(req.body || {}).length, 0);
        done();
    });

    it('With simple params', done => {
        const req = jwt.fromMethodAndPathAndBody('post', 'https://example.com/path/to/resource?a=123&b=265', {
            a: 1234,
            b: 2654
        });
        assert.equal(req.method, 'post');
        assert.equal(req.pathname, '/path/to/resource');

        const body = req.body || {};
        assert.equal(Object.keys(body).length, 2);
        assert.equal(body.a, 1234);
        assert.equal(body.b, 2654);

        assert.equal(Object.keys(req.query || {}).length, 0);
        done();
    });

    // For complex types, this is different behaviour to Express.js. So this is unsupported.
    it('With complex params the parsing is different', done => {
        const req = jwt.fromMethodAndPathAndBody(
            'post',
            'https://example.com/path/to/resource?a[type]=123&b=265&a[boop]=hello', {
              'a[type]': 1234,
              b: 2654,
              'a[boop]': 'hello_world'
            }
        );
        assert.equal(req.method, 'post');
        assert.equal(req.pathname, '/path/to/resource');

        const body = req.body || {};
        assert.equal(Object.keys(body).length, 3);
        assert.equal(body['a[type]'], 1234);
        assert.equal(body['a[boop]'], 'hello_world');
        assert.equal(body.b, 2654);

        assert.equal(Object.keys(req.query || {}).length, 0);

        done();
    });
});
