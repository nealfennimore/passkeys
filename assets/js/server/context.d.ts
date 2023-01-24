import { Request } from '@cloudflare/workers-types';
import { Env } from './env';
export interface StoredCredential {
    kid: string;
    jwk: JsonWebKey;
}
export declare class Context {
    private request;
    private env;
    private _sessionId;
    constructor(request: Request, env: Env);
    get sessionId(): string;
    get hasSession(): boolean;
    getUserId(sessionId: string): Promise<string | null>;
    getCurrentUserId(): Promise<string | null>;
    setCurrentUserId(sessionId: string, userId: string): Promise<void>;
    getChallenge(type: string): Promise<string | null>;
    setChallenge(type: string, challenge: string): Promise<void | null>;
    deleteChallenge(type: string): Promise<void | null>;
    getCredentials(userId: string): Promise<string | null>;
    getCurrentCredentials(): Promise<StoredCredential[] | null>;
    setCredentials(credentials: Array<StoredCredential>): Promise<void>;
    generateChallenge(): string;
}
