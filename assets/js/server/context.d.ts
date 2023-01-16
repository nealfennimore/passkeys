export interface UserCredential {
    kid: string;
    jwk: JsonWebKey;
}
export interface UserCredentialCache {
    userId: string;
    challenge: string;
    credentials?: [UserCredential];
}
type CacheKey = 'currentUserId' | string;
type CacheValue = string | UserCredentialCache;
export declare class Cache {
    static retrieve(key: CacheKey): Promise<any>;
    static store(key: CacheKey, value: CacheValue): Promise<void>;
}
export declare class Context {
    static getCurrentUser(): Promise<string>;
    static getCredentials(): Promise<UserCredentialCache>;
    static generateChallenge(): Promise<string>;
}
export {};
