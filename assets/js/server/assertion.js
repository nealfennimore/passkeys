import { Crypto, Digests, SigningAlg } from '../crypto';
import { concatBuffer, fromBase64Url, safeEncode, unmarshal, WebAuthnType, } from '../utils';
import * as response from './response';
export class Assertion {
    static async verify(pubKey, payload) {
        const signature = safeEncode(payload.signature);
        const authenticatorData = safeEncode(payload.authenticatorData);
        const clientDataJSON = safeEncode(payload.clientDataJSON);
        const offset = new Uint8Array(signature)[4] === 0 ? 1 : 0;
        const rawSig = concatBuffer(signature.slice(4 + offset, 36 + offset), signature.slice(-32));
        const digest = concatBuffer(authenticatorData, await crypto.subtle.digest(Digests.SHA256, clientDataJSON));
        return await crypto.subtle.verify({ name: SigningAlg.ECDSA, hash: { name: Digests.SHA256 } }, pubKey, rawSig, digest);
    }
    static async generateChallengeForCurrentUser(ctx) {
        const challenge = await ctx.generateChallenge();
        await ctx.setChallenge(WebAuthnType.Get, challenge);
        return response.json({ challenge });
    }
    static async verifyCredential(ctx, payload) {
        const { clientDataJSON, kid } = payload;
        const { challenge, type } = unmarshal(fromBase64Url(clientDataJSON));
        if (type !== WebAuthnType.Get) {
            throw new Error('Wrong credential type');
        }
        const storedChallenge = await ctx.getChallenge(WebAuthnType.Get);
        if (storedChallenge !== null && challenge !== storedChallenge) {
            throw new Error('Incorrect challenge');
        }
        const credentials = await ctx.getCurrentCredentials();
        if (!credentials?.length) {
            throw new Error('No credentials found');
        }
        const isVerified = credentials.some(async ({ kid: storedKid, jwk }) => {
            if (kid !== storedKid) {
                return false;
            }
            const key = await Crypto.fromJWK(jwk);
            return await Assertion.verify(key, payload);
        });
        await ctx.deleteChallenge(WebAuthnType.Get);
        return response.json({ isVerified });
    }
}
//# sourceMappingURL=assertion.js.map