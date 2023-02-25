import { Request } from '@cloudflare/workers-types';
import { safeDecode } from '../utils.js';
import { Cache } from './cache';
import { DB } from './db';
import { Env } from './env';

class ContextRequest {
    private _body: Promise<any>;

    constructor(request: Request) {
        this._body = request.json();
    }

    async body() {
        return await this._body;
    }
}
class ContextResponse {
    private _headers: Record<string, string> | undefined;

    get headers() {
        return this._headers;
    }

    set headers(headers: Record<string, string> | undefined) {
        this._headers = headers;
    }
}

export class Context {
    public db: DB;
    public cache: Cache;

    public request: ContextRequest;
    public response: ContextResponse;

    constructor(request: Request, env: Env) {
        this.db = new DB(env);
        this.cache = new Cache(request, env);
        this.request = new ContextRequest(request);
        this.response = new ContextResponse();
    }
    generateChallenge() {
        return safeDecode(crypto.getRandomValues(new Uint8Array(16)));
    }
}
