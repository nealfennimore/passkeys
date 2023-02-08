import {
    COSEAlgToDigest,
    COSEAlgToSigningAlg,
    COSEAlgToSigningCurve,
    Crypto,
} from '../crypto';
import {
    concatBuffer,
    safeByteEncode,
    unmarshal,
    WebAuthnOrigin,
    WebAuthnType,
} from '../utils';
import { Context } from './context';
import { StoredCredential } from './db';
import * as response from './response';
import * as schema from './schema';

export class Assertion {
    private static async verify(
        stored: StoredCredential,
        payload: schema.Assertion.VerifyPayload
    ) {
        const { coseAlg, pubkey } = stored;
        const signingAlg = COSEAlgToSigningAlg[coseAlg];
        const key = await Crypto.toCryptoKey(
            pubkey,
            signingAlg,
            COSEAlgToSigningCurve[coseAlg]
        );
        const digestAlg = COSEAlgToDigest[coseAlg];

        const signature = safeByteEncode(payload.signature);
        const authenticatorData = safeByteEncode(payload.authenticatorData);
        const clientDataJSON = safeByteEncode(payload.clientDataJSON);

        // Convert from DER ASN.1 encoding to Raw ECDSA signature
        const offset = new Uint8Array(signature)[4] === 0 ? 1 : 0;
        const rawSig = concatBuffer(
            signature.slice(4 + offset, 36 + offset),
            signature.slice(-32)
        );

        const digest = concatBuffer(
            authenticatorData,
            await crypto.subtle.digest(digestAlg, clientDataJSON)
        );

        return await crypto.subtle.verify(
            { name: signingAlg, hash: { name: digestAlg } },
            key,
            rawSig,
            digest
        );
    }

    static async generate(ctx: Context) {
        const challenge = await ctx.generateChallenge();
        await ctx.cache.setChallengeForSession(WebAuthnType.Get, challenge);

        return response.json({ challenge }, ctx.headers);
    }

    static async verifyCredential(
        ctx: Context,
        payload: schema.Assertion.VerifyPayload
    ) {
        try {
            const { clientDataJSON, kid } = payload;
            const { challenge, type, origin } = unmarshal(
                clientDataJSON
            ) as schema.ClientDataJSON;

            if (type !== WebAuthnType.Get) {
                throw new Error('Wrong credential type');
            }

            if (origin !== WebAuthnOrigin) {
                throw new Error('Key generated from wrong origin');
            }

            const storedChallenge = await ctx.cache.getChallengeForSession(
                WebAuthnType.Get
            );
            if (storedChallenge === null) {
                throw new Error('Must regenerate challenge');
            }

            if (challenge !== storedChallenge) {
                throw new Error('Incorrect challenge');
            }

            const [stored, userId] = await Promise.all([
                ctx.db.getCredentialByKid(kid),
                ctx.cache.getCurrentUserId(),
            ]);

            if (!stored) {
                throw new Error('Credential not found');
            }

            if (!userId) {
                throw new Error('User not found');
            }

            const isVerified = await Assertion.verify(stored, payload);

            // For case of multiple logins:
            // Since the user owns the key and can verify it, reset the session to point to the stored key owner's id
            if (isVerified && userId !== stored.userId) {
                await ctx.cache.setCurrentUserIdForSession(
                    ctx.cache.sessionId,
                    stored.userId
                );
            }
            return response.json({ isVerified });
        } finally {
            await ctx.cache.deleteChallengeForSession(WebAuthnType.Get);
        }
    }
}
