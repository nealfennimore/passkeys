import { Request } from '@cloudflare/workers-types';
import { parse } from 'cookie';
import { safeDecode } from '../utils.js';
import { Env } from './env';
import * as schema from './schema';

export interface StoredCredential {
    kid: string;
    jwk: JsonWebKey;
    userId: string;
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

    async getSessionUserId(sessionId: string) {
        return await this.env.sessions.get(sessionId);
    }

    async getCurrentUserId() {
        return await this.getSessionUserId(this.sessionId);
    }

    async createUser(userId: string) {
        const { success } = await this.env.DB.prepare(
            'INSERT INTO users(id) VALUES(?)'
        )
            .bind(userId)
            .run();

        if (!success) {
            throw new Error('Failed to create user');
        }
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

    async setCurrentUserIdForSession(sessionId: string, userId: string) {
        return await this.env.sessions.put(sessionId, userId, {
            expirationTtl: 60 * 60 * 24,
        });
    }

    async createCredential(
        payload: schema.Attestation.StoreCredentialPayload,
        userId: string
    ) {
        const { kid, jwk, attestationObject } = payload;
        const { success } = await this.env.DB.prepare(
            'INSERT INTO public_keys(kid, jwk, attestation_data, user_id) VALUES(?1, ?2, ?3, ?4)'
        )
            .bind(kid, jwk, attestationObject, userId)
            .run();

        if (!success) {
            throw new Error('Failed to create credential');
        }
    }

    async getCredentialByKid(kid: string) {
        return (await this.env.DB.prepare(
            'SELECT kid, jwk, user_id FROM public_keys WHERE kid = ?'
        )
            .bind(kid)
            .first()) as StoredCredential;
    }

    generateChallenge() {
        return safeDecode(crypto.getRandomValues(new Uint8Array(16)));
    }
}
