import { decode } from "../utils.js";
import { Cache, Context } from './context.js';
import { Crypto } from './crypto.js';
export class Attestation {
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
//# sourceMappingURL=attestation.js.map