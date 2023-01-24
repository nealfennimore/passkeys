import { Crypto, JwkAlg, JwkAlgToDigest, JwkAlgToSigningAlg } from '../crypto';
import {
    concatBuffer,
    fromBase64Url,
    safeEncode,
    unmarshal,
    WebAuthnType,
} from '../utils';
import { Context } from './context';
import * as response from './response';
import * as schema from './schema';

export class Assertion {
    private static async verify(
        jwk: JsonWebKey,
        payload: schema.Assertion.VerifyPayload
    ) {
        const pubKey = await Crypto.fromJWK(jwk);
        const signingAlg = JwkAlgToSigningAlg[jwk.alg as JwkAlg];
        const hashAlg = JwkAlgToDigest[jwk.alg as JwkAlg];

        const signature = safeEncode(payload.signature);
        const authenticatorData = safeEncode(payload.authenticatorData);
        const clientDataJSON = safeEncode(payload.clientDataJSON);

        // Convert from DER ASN.1 encoding to Raw ECDSA signature
        const offset = new Uint8Array(signature)[4] === 0 ? 1 : 0;
        const rawSig = concatBuffer(
            signature.slice(4 + offset, 36 + offset),
            signature.slice(-32)
        );

        const digest = concatBuffer(
            authenticatorData,
            await crypto.subtle.digest(hashAlg, clientDataJSON)
        );

        return await crypto.subtle.verify(
            { name: signingAlg, hash: { name: hashAlg } },
            pubKey,
            rawSig,
            digest
        );
    }

    static async generateChallenge(ctx: Context, userId: string) {
        const sessionId = ctx.sessionId;
        let headers;
        if (!ctx.hasSession) {
            await ctx.setCurrentUserId(sessionId, userId);
            headers = {
                'Set-Cookie': `session_id=${sessionId}; Path=/; HttpOnly; SameSite=None; Secure;`,
            };
        }

        const challenge = await ctx.generateChallenge();
        await ctx.setChallenge(WebAuthnType.Get, challenge);

        return response.json({ challenge }, headers);
    }

    static async verifyCredential(
        ctx: Context,
        payload: schema.Assertion.VerifyPayload
    ) {
        try {
            const { clientDataJSON, kid } = payload;
            const { challenge, type } = unmarshal(
                fromBase64Url(clientDataJSON)
            ) as schema.ClientDataJSON;

            if (type !== WebAuthnType.Get) {
                throw new Error('Wrong credential type');
            }

            const storedChallenge = await ctx.getChallenge(WebAuthnType.Get);
            if (storedChallenge === null) {
                throw new Error('Must regenerate challenge');
            }

            if (fromBase64Url(challenge) !== storedChallenge) {
                throw new Error('Incorrect challenge');
            }

            const credentials = await ctx.getCurrentCredentials();
            if (!credentials?.length) {
                throw new Error('No credentials found');
            }

            const isVerified = credentials.some(
                async ({ kid: storedKid, jwk }) => {
                    if (kid !== storedKid) {
                        return false;
                    }
                    return await Assertion.verify(jwk, payload);
                }
            );
            return response.json({ isVerified });
        } finally {
            ctx.deleteChallenge(WebAuthnType.Get);
        }
    }
}
