import { Crypto, Digests, SigningAlg } from '../crypto';
import { concatBuffer, decode, WebAuthnType } from '../utils';
import { Context } from './context';
import * as response from './response';

export class Assertion {
    private static async verify(
        pubKey: CryptoKey,
        assertion: AuthenticatorAssertionResponse
    ) {
        // @ts-ignore
        const { clientDataJSON, authenticatorData, signature } = assertion;

        // Convert from DER ASN.1 encoding to Raw ECDSA signature
        const offset = new Uint8Array(signature)[4] === 0 ? 1 : 0;
        const rawSig = concatBuffer(
            signature.slice(4 + offset, 36 + offset),
            signature.slice(-32)
        );

        const digest = concatBuffer(
            authenticatorData,
            await crypto.subtle.digest(Digests.SHA256, clientDataJSON)
        );

        return await crypto.subtle.verify(
            { name: SigningAlg.ECDSA, hash: { name: Digests.SHA256 } },
            pubKey,
            rawSig,
            digest
        );
    }

    static async generateChallengeForCurrentUser(ctx: Context) {
        const challenge = await ctx.generateChallenge();
        await ctx.setChallenge(WebAuthnType.Get, challenge);
        return response.json({ challenge });
    }

    static async verifyCredential(
        ctx: Context,
        credential: PublicKeyCredential
    ) {
        const r = credential.response as AuthenticatorAssertionResponse;
        const { clientDataJSON } = r;
        const { challenge, type } = JSON.parse(decode(clientDataJSON));

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

        const isVerified = credentials.some(async ({ jwk }) => {
            const key = await Crypto.fromJWK(jwk);
            return await Assertion.verify(key, r);
        });

        await ctx.deleteChallenge(WebAuthnType.Get);

        return response.json({ isVerified });
    }
}
