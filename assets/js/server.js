import { concatBuffer, decode, safeDecode } from "./utils.js";
class Cache {
    static async retrieve(key) {
        const item = window.localStorage.getItem(key);
        return item ? JSON.parse(item) : {};
    }
    static async store(key, value) {
        window.localStorage.setItem(key, JSON.stringify(value));
    }
}
class Context {
    static async getCurrentUser() {
        return await Cache.retrieve('currentUserId');
    }
    static async getCredentials() {
        const userId = await Context.getCurrentUser();
        return await Cache.retrieve(userId);
    }
    static async generateChallenge() {
        return safeDecode(crypto.getRandomValues(new Uint8Array(16)));
    }
}
class Crypto {
    static async toCryptoKey(pubKey) {
        return await crypto.subtle.importKey('spki', pubKey, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
    }
    static async toJWK(pubKey) {
        return await crypto.subtle.exportKey('jwk', pubKey);
    }
    static async fromJWK(jwk) {
        return await crypto.subtle.importKey('jwk', jwk, { name: "ECDSA", namedCurve: "P-256" }, true, ['verify']);
    }
}
class Attestation {
    static async generateUser() {
        const userId = window.crypto.randomUUID();
        const challenge = await Context.generateChallenge();
        const credentials = {
            userId,
            challenge,
        };
        Cache.store('currentUserId', userId);
        Cache.store(userId, credentials);
        return credentials;
    }
    static async storeCredential(credential) {
        const response = credential.response;
        const { clientDataJSON } = response;
        const pubKey = response.getPublicKey();
        const { challenge, type } = JSON.parse(decode(clientDataJSON));
        if (type !== 'webauthn.create') {
            throw new Error("Wrong credential type");
        }
        const currentCredentials = await Context.getCredentials();
        const { credentials = [], challenge: storedChallenge } = currentCredentials;
        if (challenge !== storedChallenge) {
            throw new Error("Incorrect challenge");
        }
        Cache.store(currentCredentials.userId, {
            ...currentCredentials,
            credentials: [
                ...credentials,
                {
                    kid: credential.id,
                    jwk: await Crypto.toJWK(await Crypto.toCryptoKey(pubKey))
                }
            ]
        });
    }
}
class Assertion {
    static async verify(pubKey, assertion) {
        const { clientDataJSON, authenticatorData, signature } = assertion.response;
        const offset = new Uint8Array(signature)[4] === 0 ? 1 : 0;
        const rawSig = concatBuffer(signature.slice(4 + offset, 36 + offset), signature.slice(-32));
        const digest = concatBuffer(authenticatorData, await crypto.subtle.digest('SHA-256', clientDataJSON));
        return await crypto.subtle.verify({ name: "ECDSA", hash: { name: "SHA-256" } }, pubKey, rawSig, digest);
    }
    static async generateChallengeForCurrentUser() {
        const challenge = await Context.generateChallenge();
        const currentCredentials = await Context.getCredentials();
        const credentials = {
            ...currentCredentials,
            challenge,
        };
        Cache.store(currentCredentials.userId, credentials);
        return challenge;
    }
    static async verifyCredential(credential) {
        const response = credential.response;
        const { clientDataJSON } = response;
        const { challenge, type } = JSON.parse(decode(clientDataJSON));
        if (type !== 'webauthn.get') {
            throw new Error("Wrong credential type");
        }
        const currentCredentials = await Context.getCredentials();
        const { credentials = [], challenge: storedChallenge } = currentCredentials;
        if (challenge !== storedChallenge) {
            throw new Error("Incorrect challenge");
        }
        if (!credentials.length) {
            throw new Error("No credentials found");
        }
        return credentials.some(async ({ jwk }) => {
            const key = await Crypto.fromJWK(jwk);
            return await Assertion.verify(key, response);
        });
    }
}
export class API {
}
API.getChallenge = Context.generateChallenge;
API.Attestation = Attestation;
API.Assertion = Assertion;
//# sourceMappingURL=server.js.map