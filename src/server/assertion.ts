import {
    COSEAlgToDigest,
    COSEAlgToSigningAlg,
    COSEAlgToSigningCurve,
    Crypto,
} from '../crypto';
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
        pubkey: ArrayBuffer,
        coseAlg: number,
        payload: schema.Assertion.VerifyPayload
    ) {
        const signingAlg = COSEAlgToSigningAlg[coseAlg];
        const key = await Crypto.toCryptoKey(
            pubkey,
            signingAlg,
            COSEAlgToSigningCurve[coseAlg]
        );
        const digestAlg = COSEAlgToDigest[coseAlg];

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
        await ctx.setChallengeForSession(WebAuthnType.Get, challenge);

        return response.json({ challenge }, ctx.headers);
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

            const storedChallenge = await ctx.getChallengeForSession(
                WebAuthnType.Get
            );
            if (storedChallenge === null) {
                throw new Error('Must regenerate challenge');
            }

            if (challenge !== storedChallenge) {
                throw new Error('Incorrect challenge');
            }

            const {
                pubkey,
                userId: storedUserId,
                coseAlg,
            } = await ctx.getCredentialByKid(kid);
            const userId = await ctx.getCurrentUserId();
            if (userId !== storedUserId) {
                throw new Error('User does not own key');
            }

            const isVerified = await Assertion.verify(pubkey, coseAlg, payload);
            return response.json({ isVerified });
        } finally {
            await ctx.deleteChallengeForSession(WebAuthnType.Get);
        }
    }
}
