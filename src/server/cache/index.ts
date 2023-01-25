import { Request } from '@cloudflare/workers-types';
import { parse } from 'cookie';
import { Env } from '../env';

export class Cache {
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
}
