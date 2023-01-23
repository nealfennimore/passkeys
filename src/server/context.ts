import { Request } from '@cloudflare/workers-types';
import {
    fromBase64Url,
    marshal,
    safeDecode,
    toBase64Url,
    unmarshal,
} from '../utils.js';
import { Env } from './env';

export interface StoredCredential {
    kid: string;
    jwk: JsonWebKey;
}

export class Context {
    private request: Request;
    private env: Env;
    private _sessionId: string | null;

    constructor(request: Request, env: Env) {
        this.request = request;
        this.env = env;
        this._sessionId = null;
    }

    get sessionId() {
        if (this._sessionId) {
            return this._sessionId;
        }
        this._sessionId =
            this.request.headers.get('sessionId') ?? crypto.randomUUID();
        return this._sessionId;
    }

    get hasSession() {
        const sessionId = this.request.headers.get('sessionId');
        if (!sessionId) {
            return false;
        }
        return !!this.getUserId(sessionId);
    }

    async getUserId(sessionId: string) {
        return await this.env.sessions.get(sessionId);
    }

    async getCurrentUserId() {
        return await this.getUserId(this.sessionId);
    }

    async setCurrentUserId(sessionId: string, userId: string) {
        return await this.env.sessions.put(sessionId, userId);
    }

    async getChallenge(type: string) {
        const userId = await this.getCurrentUserId();
        if (!userId) {
            return null;
        }
        return await this.env.challenges.get(`${userId}:${type}`);
    }

    async setChallenge(type: string, challenge: string) {
        const userId = await this.getCurrentUserId();
        if (!userId) {
            return null;
        }
        return await this.env.challenges.put(`${userId}:${type}`, challenge, {
            expirationTtl: 60 * 5,
        });
    }

    async deleteChallenge(type: string) {
        const userId = await this.getCurrentUserId();
        if (!userId) {
            return null;
        }
        return await this.env.challenges.delete(`${userId}:${type}`);
    }

    async getCredentials(userId: string) {
        return await this.env.pubkeys.get(userId);
    }

    async getCurrentCredentials() {
        const userId = await this.getCurrentUserId();
        if (!userId) {
            return null;
        }
        const credentials = await this.getCredentials(userId);
        if (!credentials) {
            return null;
        }
        return unmarshal(fromBase64Url(credentials)) as Array<StoredCredential>;
    }

    async setCredentials(credentials: Array<StoredCredential>) {
        const userId = await this.getCurrentUserId();
        if (!userId) {
            return;
        }
        const storedCredentials = (await this.getCurrentCredentials()) ?? [];
        const combinedCredentials = [...storedCredentials, ...credentials];
        return await this.env.pubkeys.put(
            userId,
            toBase64Url(marshal(combinedCredentials)),
            { expirationTtl: 60 * 60 * 24 }
        );
    }

    generateChallenge() {
        return safeDecode(crypto.getRandomValues(new Uint8Array(16)));
    }
}
