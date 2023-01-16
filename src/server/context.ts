import { safeDecode } from "../utils.js";

export interface UserCredential {
    kid: string;
    jwk: JsonWebKey;
}

export interface UserCredentialCache {
    userId: string;
    challenge: string;
    credentials?: [UserCredential]
}

type CacheKey = 'currentUserId' | string
type CacheValue = string | UserCredentialCache;

export class Cache {
    static async retrieve(key: CacheKey) {
        const item = window.localStorage.getItem(key);
        return item ? JSON.parse(item) : {};
    }
    static async store(key: CacheKey, value: CacheValue) {
        window.localStorage.setItem(key, JSON.stringify(value));
    }
}

export class Context {
    static async getCurrentUser(){
        return await Cache.retrieve('currentUserId') as string;
    }

    static async getCredentials(){
        const userId = await Context.getCurrentUser();
        return await Cache.retrieve(userId) as UserCredentialCache;
    }

    static async generateChallenge(){
        return safeDecode(crypto.getRandomValues(new Uint8Array(16)))
    }
}