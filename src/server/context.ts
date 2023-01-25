import { Request } from '@cloudflare/workers-types';
import { safeDecode } from '../utils.js';
import { Cache } from './cache';
import { DB } from './db';
import { Env } from './env';

export class Context {
    private _headers: Record<string, string> | undefined;
    // Body from the request
    private _body: Record<string, any> | undefined;

    public db: DB;
    public cache: Cache;

    constructor(request: Request, env: Env) {
        this.db = new DB(env);
        this.cache = new Cache(request, env);
    }

    get headers() {
        return this._headers;
    }

    set headers(headers: Record<string, string> | undefined) {
        this._headers = headers;
    }

    get body() {
        return this._body;
    }

    set body(data: Record<string, any> | undefined) {
        this._body = data;
    }

    generateChallenge() {
        return safeDecode(crypto.getRandomValues(new Uint8Array(16)));
    }
}
