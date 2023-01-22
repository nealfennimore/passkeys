import { Request } from '@cloudflare/workers-types';
import { fromBase64Url, marshal, safeDecode, toBase64Url, unmarshal } from "../utils.js";
import { Env } from "./env";

export interface StoredCredential {
    kid: string;
    jwk: JsonWebKey;
}

export class Context {
    private request: Request;
    private env: Env;

    constructor(request: Request, env: Env){
        this.request = request;
        this.env = env;
    }

    get sessionId() {
        return this.request.headers.get('sessionId');
    }

    async getCurrentUserId(){
        const sessionId = this.sessionId;
        if (!sessionId) {
            return null;
        }
        return await this.env.sessions.get(sessionId);
    }

    async setCurrentUserId(sessionId: string, userId: string){
        return await this.env.sessions.put(sessionId, userId);
    }

    async getChallenge(type: string){
        const userId = await this.getCurrentUserId();
        if(!userId){
            return null;
        }
        return await this.env.challenges.get(`${userId}:${type}`);
    }

    async setChallenge(type: string, challenge: string){
        const userId = await this.getCurrentUserId();
        if(!userId){
            return null;
        }
        return await this.env.challenges.put(`${userId}:${type}`, challenge, {expirationTtl: 60 * 5})
    }

    async deleteChallenge(type: string){
        const userId = await this.getCurrentUserId();
        if(!userId){
            return null;
        }
        return await this.env.challenges.delete(`${userId}:${type}`)
    }

    async getCredentials(){
        const userId = await this.getCurrentUserId();
        if(!userId){
            return null;
        }
        const creds = await this.env.pubkeys.get(userId);
        if(!creds){
            return null;
        }
        return unmarshal(fromBase64Url(creds)) as Array<StoredCredential>;
    }

    async setCredentials(credentials: Array<StoredCredential>){
        const userId = await this.getCurrentUserId();
        if(!userId){
            return null;
        }
        const storedCredentials = await this.getCredentials() ?? [];
        const combinedCredentials = [...storedCredentials, ...credentials];
        return await this.env.pubkeys.put(userId, toBase64Url(marshal(combinedCredentials)), {expirationTtl: 60 * 60 * 24});
    }

    generateChallenge(){
        return safeDecode(crypto.getRandomValues(new Uint8Array(16)));
    }
}