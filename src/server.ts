import { decode, safeDecode } from "./utils.js";

interface UserCredential {
    kid: string;
    jwk: JsonWebKey;
}

interface UserCredentialCache {
    userId: string;
    challenge: string;
    credentials?: [UserCredential]
}

type CacheKey = 'currentUserId' | string
type CacheValue = string | UserCredentialCache;

class Cache {
    static async retrieve(key: CacheKey) {
        const item = window.localStorage.getItem(key);
        return item ? JSON.parse(item) : {};
    }
    static async store(key: CacheKey, value: CacheValue) {
        window.localStorage.setItem(key, JSON.stringify(value));
    }

    static async getCurrentUser(){
        return await Cache.retrieve('currentUserId') as string;
    }

    static async getCredentials(){
        const userId = await Cache.getCurrentUser();
        return await Cache.retrieve(userId) as UserCredentialCache;
    }
}

class Crypto {

    static concatBuffer(buffer1: ArrayBuffer, buffer2: ArrayBuffer) {
        var tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
        tmp.set(new Uint8Array(buffer1), 0);
        tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
        return tmp.buffer;
    }

    static async toCryptoKey(pubKey: ArrayBuffer) {
        return await crypto.subtle.importKey(
            'spki',
            pubKey,
            {name:'ECDSA', namedCurve: 'P-256'},
            true,
            ['verify']
        );
    }

    static async toJWK(pubKey: CryptoKey) {
        return await crypto.subtle.exportKey('jwk', pubKey);
    }
    static async fromJWK(jwk: JsonWebKey) {
        return await crypto.subtle.importKey('jwk', jwk, {name: "ECDSA", namedCurve: "P-256"}, true, ['verify']);
    }

    static async verify(pubKey: CryptoKey, assertion: AuthenticatorAssertionResponse) {
        // @ts-ignore
        const { clientDataJSON, authenticatorData, signature } = assertion.response;

        // Convert from DER ASN.1 encoding to Raw ECDSA signature
        const offset = new Uint8Array(signature)[4] === 0 ? 1 : 0;
        const rawSig = Crypto.concatBuffer(
            signature.slice(4 + offset, 36 + offset),
            signature.slice(-32),
        );

        const digest = Crypto.concatBuffer(
            authenticatorData,
            await crypto.subtle.digest('SHA-256', clientDataJSON)
        );

        return await crypto.subtle.verify(
            {name: "ECDSA", hash: { name: "SHA-256"} },
            pubKey,
            rawSig,
            digest
        );
    }
}

class Attestation {
    static async generateUser(){
        const userId = window.crypto.randomUUID();
        const challenge = await API.getChallenge();
        const credentials: UserCredentialCache = {
            userId,
            challenge: safeDecode(challenge)
        };
        Cache.store('currentUserId', userId);
        Cache.store(userId, credentials);
        return credentials;
    }
    
    static async storeCredential(credential: PublicKeyCredential) {
        const response = credential.response as AuthenticatorAttestationResponse;
        const { clientDataJSON } = response;
        const pubKey = response.getPublicKey() as ArrayBuffer;

        const { challenge, type } = JSON.parse(decode(clientDataJSON))

        if (type !== 'webauthn.create') {
            throw new Error("Wrong credential type")
        }

        const currentCredentials = await Cache.getCredentials();
        const { credentials = [], challenge: storedChallenge } = currentCredentials;
        
        if (challenge !== storedChallenge){
            throw new Error("Incorrect challenge");
        }
        
        Cache.store(currentCredentials.userId, {
            ...currentCredentials,
            credentials: [
                ...credentials,
                // @ts-ignore
                {
                    kid: credential.id,
                    jwk: await Crypto.toJWK(await Crypto.toCryptoKey(pubKey))
                }
                
            ]
        });
    }
}

class Assertion {
    static async getChallengeForCurrentUser(userId: string){
        const challenge = await API.getChallenge();
        const currentCredentials = await Cache.getCredentials();
        const credentials: UserCredentialCache = {
            ...currentCredentials,
            challenge: safeDecode(challenge)
        };
        Cache.store(userId, credentials);
        return credentials;
    }

    static async verifyCredential(credential: PublicKeyCredential) {
        const response = credential.response as AuthenticatorAssertionResponse;
        const { clientDataJSON } = response;
        const { challenge, type } = JSON.parse(decode(clientDataJSON))

        if (type !== 'webauthn.get') {
            throw new Error("Wrong credential type")
        }

        const currentCredentials = await Cache.getCredentials();
        const { credentials = [], challenge: storedChallenge } = currentCredentials;

        if (challenge !== storedChallenge){
            throw new Error("Incorrect challenge");
        }

        if (!credentials.length){
            throw new Error("No credentials found");
        }
        
        return credentials.some(async ({jwk})=>{
            const key = await Crypto.fromJWK(jwk);
            return await Crypto.verify(key, response);
        })
    }
}

export class API {
    static async getChallenge(){
        return crypto.getRandomValues(new Uint8Array(16))
    }

    static Attestation = Attestation;
    static Assertion = Assertion;
}