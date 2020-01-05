/*
 * Based off jwt-simple:
 * https://github.com/hokaccha/node-jwt-simple
 *
 * Add Atlassian query string hash verification:
 * https://developer.atlassian.com/cloud/jira/platform/understanding-jwt/
 *
 * JSON Web Token encode and decode module for node.js
 *
 * Copyright(c) 2011 Kazuhito Hokamura
 * MIT Licensed
 */

import { createHash, createHmac } from 'crypto';
import Uri from 'jsuri';
import * as url from 'url';
import { Request as ExpressRequest } from 'express';

// https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
export enum Algorithm {
    HS256 = 'HS256',
    HS384 = 'HS384',
    HS512 = 'HS512'
}

function getAlgorithmFromString(rawAlgorithm: string): Algorithm | undefined {
    switch (rawAlgorithm) {
        case 'HS256':
            return Algorithm.HS256;
        case 'HS384':
            return Algorithm.HS384;
        case 'HS512':
            return Algorithm.HS512;
        default:
            return undefined;
    }
}

type Hash = 'sha256' | 'sha384' | 'sha512';

/**
 * Supported algorithm mapping.
 */
const algorithmMap: { [alg in Algorithm]: Hash } = {
    HS256: 'sha256',
    HS384: 'sha384',
    HS512: 'sha512'
};

export function fromExpressRequest(eReq: ExpressRequest): Request {
    // req.originalUrl represents the full URL and req.path represents the URL from the last router
    // (https://expressjs.com/en/4x/api.html#req.originalUrl)
    // However, since some people depend on this lib without using real req object but rather mock them, we need this
    // fallback for it to not break.
    const pathname = (eReq.originalUrl ? url.parse(eReq.originalUrl).pathname : eReq.path) || undefined;
    return {
        method: eReq.method,
        pathname,
        query: eReq.query,
        body: eReq.body
    };
}

export function fromMethodAndUrl(method: string, rawUrl: string): Request {
    const parsedUrl = url.parse(rawUrl, true);

    return {
        method,
        pathname: parsedUrl.pathname || undefined,
        query: parsedUrl.query
    };
}

export function fromMethodAndPathAndBody(
    method: 'put' | 'post' | 'delete',
    rawUrl: string,
    body: Params): Request {
    const parsedUrl = url.parse(rawUrl, false);

    return {
        method,
        pathname: parsedUrl.pathname || undefined,
        body
    };
}

export type Params = {
    [param: string]: any; // tslint:disable-line:no-any
};

/**
 * Fields from an incoming HTTP Request object that are used to generate a signed JWT.
 */
export type Request = {
    /**
     * The HTTP method of this request. GET, PUT, POST, DELETE etc
     */
    method: string;

    /**
     * The pathname of this request, should give the same result as calling
     * {@link https://nodejs.org/api/url.html#url_url_pathname uri.pathname}.
     */
    pathname?: string;

    /**
     * The query parameters on this request. Should match the same structure as
     * the {@link https://expressjs.com/en/api.html#req.query req.query} from Express.js.
     */
    query?: Params;

    /**
     * The body parameters on this request. Should match the same structure as
     * the {@link https://expressjs.com/en/api.html#req.body req.body} from Express.js.
     */
    body?: Params;
};

/**
 * The separator between sections of a canonical query.
 */
const CANONICAL_QUERY_SEPARATOR = '&';

export const version = '1.0.3';

/**
 * Decodes JWT string to object.
 * The encoding algorithm must be HS256, HS384, or HS512.
 *
 * @param token JWT to decode
 * @param key Key used to decode
 * @param noVerify optional, set to true to skip the result verification
 *
 * @return Decoded JWT object
 *
 * @api public
 */
export const decode = function jwt_decode(token: string, key: string, noVerify?: boolean) {
    // Check seguments
    const segments = token.split('.');
    if (segments.length !== 3) {
        throw new Error('Not enough or too many JWT token segments; should be 3');
    }

    // All segment should be base64
    const headerSeg = segments[0];
    const payloadSeg = segments[1];
    const signatureSeg = segments[2];

    // Base64 decode and parse JSON
    const header = JSON.parse(base64urlDecode(headerSeg));
    const payload = JSON.parse(base64urlDecode(payloadSeg));

    // Normalize 'aud' claim, the spec allows both String and Array
    if (payload.aud && !Array.isArray(payload.aud)) {
        payload.aud = [payload.aud];
    }

    if (!noVerify) {
        verifySignature(headerSeg, payloadSeg, signatureSeg, key, header.alg);
    }

    return payload;
};

/**
 * Encodes JWT object to string.
 *
 * @param payload Payload object to encode
 * @param key Key used to encode
 * @param algorithm Optional, must be HS256, HS384, or HS512; default is HS256
 *
 * @return Encoded JWT string
 *
 * @api public
 */
export const encode = function jwt_encode(payload: object, key: string, algorithm?: Algorithm): string {
    const [signingAlgorithm, signingMethod] = validateAlgorithm(key, algorithm);

    // typ is fixed value
    const header = { typ: 'JWT', alg: signingAlgorithm };

    // Create segments, all segment should be base64 string
    const segments = [];
    segments.push(base64urlEncode(JSON.stringify(header)));
    segments.push(base64urlEncode(JSON.stringify(payload)));
    segments.push(sign(segments.join('.'), key, signingMethod));

    return segments.join('.');
};

export function createCanonicalRequest(req: Request, checkBodyForParams?: boolean, baseUrl?: string): string {
    return canonicalizeMethod(req) +
        CANONICAL_QUERY_SEPARATOR +
        canonicalizeUri(req, baseUrl) +
        CANONICAL_QUERY_SEPARATOR +
        canonicalizeQueryString(req, checkBodyForParams);
}

export function createQueryStringHash(req: Request, checkBodyForParams?: boolean, baseUrl?: string): string {
    return createHash(algorithmMap.HS256)
        .update(createCanonicalRequest(req, checkBodyForParams, baseUrl))
        .digest('hex');
}

/**
 * Private util functions.
 */

function validateAlgorithm(key: string, algorithm?: string): [string, Hash] {
    // Check key
    if (!key) {
        throw new Error('Require key');
    }

    // Check algorithm, default is HS256
    const signingAlgorithm = algorithm || 'HS256';
    const alg = getAlgorithmFromString(signingAlgorithm);
    if (!alg) {
        throw new Error('Algorithm "' + algorithm + '" is not supported');
    }

    const signingMethod = algorithmMap[alg];
    if (!signingMethod) {
        throw new Error('Algorithm "' + algorithm + '" is not supported');
    }

    return [signingAlgorithm, signingMethod];
}

function verifySignature(headerSeg: string, payloadSeg: string, signatureSeg: string, key: string, algorithm?: string) {
    const [, signingMethod] = validateAlgorithm(key, algorithm);

    // Verify signature
    const signingInput = [headerSeg, payloadSeg].join('.');
    if (signatureSeg !== sign(signingInput, key, signingMethod)) {
        throw new Error(
            'Signature verification failed for input: ' + signingInput + ' with method ' + signingMethod
        );
    }
}

function sign(input: string, key: string, method: Hash): string {
    const base64str = createHmac(method, key).update(input).digest('base64');
    return base64urlEscape(base64str);
}

function base64urlDecode(str: string): string {
    return Buffer.from(base64urlUnescape(str), 'base64').toString();
}

function base64urlUnescape(str: string): string {
    str += Array(5 - str.length % 4).join('=');
    return str.replace(/\-/g, '+').replace(/_/g, '/');
}

function base64urlEncode(str: string): string {
    return base64urlEscape(Buffer.from(str).toString('base64'));
}

function base64urlEscape(str: string): string {
    return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function canonicalizeMethod(req: Request): string {
    return req.method.toUpperCase();
}

function canonicalizeUri(req: Request, baseUrlString?: string) {
    let path = req.pathname;
    const baseUrl = new Uri(baseUrlString);
    const baseUrlPath = baseUrl.path();

    if (path && path.indexOf(baseUrlPath) === 0) {
        path = path.slice(baseUrlPath.length);
    }

    if (!path || path.length === 0) {
        return '/';
    }

    // If the separator is not URL encoded then the following URLs have the same query-string-hash:
    //   https://djtest9.jira-dev.com/rest/api/2/project&a=b?x=y
    //   https://djtest9.jira-dev.com/rest/api/2/project?a=b&x=y
    path = path.replace(new RegExp(CANONICAL_QUERY_SEPARATOR, 'g'), encodeRfc3986(CANONICAL_QUERY_SEPARATOR));

    // Prefix with /
    if (path[0] !== '/') {
        path = '/' + path;
    }

    // Remove trailing /
    if (path.length > 1 && path[path.length - 1] === '/') {
        path = path.substring(0, path.length - 1);
    }

    return path;
}

function canonicalizeQueryString(req: Request, checkBodyForParams?: boolean): string {
    let queryParams = req.query;
    const method = req.method.toUpperCase();

    // Apache HTTP client (or something) sometimes likes to take the query string and put it into the request body
    // if the method is PUT or POST
    if (checkBodyForParams && Object.keys(queryParams || {}).length === 0 && (method === 'POST' || method === 'PUT')) {
        queryParams = req.body;
    }

    const sortedQueryString = new Array<string>();
    const query: { [key: string]: any; } = { ...queryParams };
    if (Object.keys(query).length !== 0) {
        // Remove the 'jwt' query string param
        delete query.jwt;

        const queryKeys = Object.keys(query);
        queryKeys.sort();

        queryKeys.forEach(key => {
            // The __proto__ field can sometimes sneak in depending on what node version is being used.
            // Get rid of it or the qsh calculation will be wrong.
            if (key === '__proto__') {
                return;
            }
            const param = query[key];
            let paramValue = '';
            if (Array.isArray(param)) {
                param.sort();
                paramValue = param.map(encodeRfc3986).join(',');
            } else {
                paramValue = encodeRfc3986(param);
            }
            sortedQueryString.push(encodeRfc3986(key) + '=' + paramValue);
        });
    }
    return sortedQueryString.join('&');
}

/**
 * We follow the same rules as specified in OAuth1:
 * Percent-encode everything but the unreserved characters according to RFC-3986:
 * unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
 * See http://tools.ietf.org/html/rfc3986
 */
function encodeRfc3986(value: string): string {
    return encodeURIComponent(value)
        .replace(/[!'()]/g, escape)
        .replace(/\*/g, '%2A');
}
