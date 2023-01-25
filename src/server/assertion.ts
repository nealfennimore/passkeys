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
    WebAuthnType,
} from '../utils';
import { Context, StoredCredential } from './context';
import * as response from './response';
import * as schema from './schema';

export class Assertion {
    private static async verify(
        stored: StoredCredential,
        payload: schema.Assertion.VerifyPayload
    ) {
        const { coseAlg, pubkey } = stored;
        // DEBUG:
        console.log(Array.from(new Uint8Array(pubkey)));
        // DEBUG:
        console.log(stored.pubkey.byteLength);
        const signingAlg = COSEAlgToSigningAlg[coseAlg];
        // DEBUG:
        console.log(coseAlg);
        // DEBUG:
        console.log(signingAlg);
        // DEBUG:
        console.log(COSEAlgToSigningCurve[coseAlg]);
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
                clientDataJSON
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

            const stored = await ctx.getCredentialByKid(kid);
            const userId = await ctx.getCurrentUserId();
            if (userId !== stored.userId) {
                throw new Error('User does not own key');
            }

            const isVerified = await Assertion.verify(stored, payload);
            return response.json({ isVerified });
        } finally {
            await ctx.deleteChallengeForSession(WebAuthnType.Get);
        }
    }
}
