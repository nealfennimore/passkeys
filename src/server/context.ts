import { fromBase64Url, marshal, safeDecode, toBase64Url, unmarshal } from "../utils.js";

export interface UserCredential {
    kid: string;
    jwk: JsonWebKey;
}

export class Context {
    private request: Request;

    constructor(request: Request){
        this.request = request;
    }

    async getCurrentUserId(){
        return await sessions.get(this.request.headers.get('sessionId')) as string;
    }

    async setCurrentUserId(sessionId: string, userId: string){
        return await sessions.set(sessionId, userId);
    }

    async getChallenge(type: string){
        const userId = await this.getCurrentUserId();
        return await challenges.get(`${userId}:${type}`) ?? null;
    }

    async setChallenge(type: string, challenge: string | null){
        const userId = await this.getCurrentUserId();
        return await challenges.set(`${userId}:${type}`, challenge)
    }

    async getCredentials(){
        const userId = await this.getCurrentUserId();
        const creds = await pubkeys.get(userId);
        return unmarshal(fromBase64Url(creds)) as Array<UserCredential>;
    }

    async setCredentials(credentials: Array<UserCredential>){
        const userId = await this.getCurrentUserId();
        return await pubkeys.set(userId, toBase64Url(marshal(credentials)));
    }

    async generateChallenge(){
        return safeDecode(crypto.getRandomValues(new Uint8Array(16)))
    }
}