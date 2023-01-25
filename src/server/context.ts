import { Request } from '@cloudflare/workers-types';
import { parse } from 'cookie';
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

type Cookie = {
    session_id?: string;
};

export class Context {
    private request: Request;
    private env: Env;
    private _sessionId: string | null;
    // Headers that should be outgoing with the response
    private _headers: Record<string, string> | undefined;
    // Body from the request
    private _body: Record<string, any> | undefined;

    constructor(request: Request, env: Env) {
        this.request = request;
        this.env = env;
        this._sessionId = null;
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

    get sessionId() {
        if (this._sessionId) {
            return this._sessionId;
        }
        this._sessionId = this.cookieSessionId ?? crypto.randomUUID();
        return this._sessionId;
    }
    get hasSession() {
        return !!this.cookieSessionId;
    }

    get cookieSessionId() {
        const cookie = parse(this.request.headers.get('Cookie') ?? '');
        return cookie.session_id || null;
    }

    async getUserId(sessionId: string) {
        return await this.env.sessions.get(sessionId);
    }

    async getCurrentUserId() {
        return await this.getUserId(this.sessionId);
    }

    async setCurrentUserIdForSession(sessionId: string, userId: string) {
        return await this.env.sessions.put(sessionId, userId, {
            expirationTtl: 60 * 60 * 24,
        });
    }

    async getChallengeForSession(type: string) {
        const sessionId = this.sessionId;
        if (!sessionId) {
            return null;
        }
        return await this.env.challenges.get(`${sessionId}:${type}`);
    }

    async setChallengeForSession(type: string, challenge: string) {
        const sessionId = this.sessionId;
        if (!sessionId) {
            return null;
        }
        return await this.env.challenges.put(
            `${sessionId}:${type}`,
            challenge,
            {
                expirationTtl: 60 * 5,
            }
        );
    }

    async deleteChallengeForSession(type: string) {
        const sessionId = this.sessionId;
        if (!sessionId) {
            return null;
        }
        return await this.env.challenges.delete(`${sessionId}:${type}`);
    }

    async getUserIdByKid(kid: string) {
        return await this.env.pubkeys.get(`kid:${kid}`);
    }

    async setUserIdForKid(kid: string, userId: string) {
        return await this.env.pubkeys.put(`kid:${kid}`, userId, {
            expirationTtl: 60 * 60 * 24,
        });
    }

    async getCredentialsByUserId(userId: string) {
        return await this.env.pubkeys.get(`user:${userId}`);
    }

    async setCredentialsForUserId(
        userId: string,
        credentials: Array<StoredCredential>
    ) {
        return await this.env.pubkeys.put(
            `user:${userId}`,
            toBase64Url(marshal(credentials)),
            {
                expirationTtl: 60 * 60 * 24,
            }
        );
    }

    async getCredentialsByKid(kid: string) {
        const userId = await this.getUserIdByKid(kid);
        if (!userId) {
            return null;
        }
        const credentials = await this.getCredentialsByUserId(userId);
        if (!credentials) {
            return null;
        }
        return unmarshal(fromBase64Url(credentials)) as Array<StoredCredential>;
    }

    async getCurrentCredentials() {
        const userId = await this.getCurrentUserId();
        if (!userId) {
            return null;
        }
        const credentials = await this.env.pubkeys.get(userId);
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
        return await this.setCredentialsForUserId(userId, combinedCredentials);
    }

    async setKidForCurrentUser(credentials: Array<StoredCredential>) {
        const userId = await this.getCurrentUserId();
        if (!userId) {
            return;
        }
        return await Promise.all(
            credentials.map(({ kid }) => this.setUserIdForKid(kid, userId))
        );
    }

    generateChallenge() {
        return safeDecode(crypto.getRandomValues(new Uint8Array(16)));
    }
}
