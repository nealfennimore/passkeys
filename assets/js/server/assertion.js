import { concatBuffer, decode } from "../utils.js";
import { Cache, Context } from './context.js';
import { Crypto, Digests, SigningAlg } from './crypto.js';
export class Assertion {
    static async verify(pubKey, assertion) {
        const { clientDataJSON, authenticatorData, signature } = assertion.response;
        const offset = new Uint8Array(signature)[4] === 0 ? 1 : 0;
        const rawSig = concatBuffer(signature.slice(4 + offset, 36 + offset), signature.slice(-32));
        const digest = concatBuffer(authenticatorData, await crypto.subtle.digest(Digests.SHA256, clientDataJSON));
        return await crypto.subtle.verify({ name: SigningAlg.ECDSA, hash: { name: Digests.SHA256 } }, pubKey, rawSig, digest);
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
//# sourceMappingURL=assertion.js.map