import {
    COSEAlgToDigest,
    COSEAlgToSigningAlg,
    COSEAlgToSigningCurve,
    Crypto,
    stringTimingSafeEqual,
} from '../crypto';
import {
    concatBuffer,
    isBiggerBuffer,
    isEqualBuffer,
    safeByteEncode,
    unmarshal,
} from '../utils';
import {
    WebAuthnOrigin,
    WebAuthnOriginSHA256Hash,
    WebAuthnType,
} from './constants';
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

            const authenticatorData = safeByteEncode(payload.authenticatorData);
            const rpIdHash = authenticatorData.slice(0, 32);

            if (type !== WebAuthnType.Get) {
                throw new Error('Wrong credential type');
            }

            if (
                origin !== WebAuthnOrigin ||
                !isEqualBuffer(rpIdHash, await WebAuthnOriginSHA256Hash)
            ) {
                throw new Error('Key generated from wrong origin');
            }

            const storedChallenge = await ctx.cache.getChallengeForSession(
                WebAuthnType.Get
            );
            if (storedChallenge === null) {
                throw new Error('Must regenerate challenge');
            }

            if (!stringTimingSafeEqual(challenge, storedChallenge)) {
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
            if (!isVerified) {
                throw new Error('Invalid signature');
            }

            const signCounter = authenticatorData.slice(33, 37);
            // Ensure the signing counter has been incremented
            if (
                stored?.signCounter &&
                !isBiggerBuffer(signCounter, stored?.signCounter)
            ) {
                throw new Error('Signing counter value invalid');
            }
            await ctx.db.updateCredentialSigningCounter(kid, signCounter);

            // For case of multiple logins:
            // Since the user owns the key and can verify it, reset the session to point to the stored key owner's id
            if (userId !== stored.userId) {
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
