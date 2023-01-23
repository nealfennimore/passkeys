import { Crypto } from '../crypto';
import { decode, WebAuthnType } from '../utils';
import { Context } from './context';
import * as response from './response';

export class Attestation {
    static async generate(ctx: Context, userId: string) {
        const sessionId = ctx.sessionId;
        if (!ctx.hasSession) {
            await ctx.setCurrentUserId(sessionId, userId);
        }

        const challenge = ctx.generateChallenge();
        await ctx.setChallenge(WebAuthnType.Create, challenge);

        return response.json(
            { challenge },
            {
                'Set-Cookie': `session_id=${sessionId}; Path=/; HttpOnly; SameSite=None; Secure;`,
            }
        );
    }

    static async storeCredential(
        ctx: Context,
        credential: PublicKeyCredential
    ) {
        const r = credential.response as AuthenticatorAttestationResponse;
        const { clientDataJSON } = r;
        const pubKey = r.getPublicKey() as ArrayBuffer;

        const { challenge, type } = JSON.parse(decode(clientDataJSON));

        if (type !== WebAuthnType.Create) {
            throw new Error('Wrong credential type');
        }

        const storedChallenge = ctx.getChallenge(type);

        if (storedChallenge !== null && challenge !== storedChallenge) {
            throw new Error('Incorrect challenge');
        }

        await Promise.all([
            ctx.deleteChallenge(WebAuthnType.Create),
            ctx.setCredentials([
                {
                    kid: credential.id,
                    jwk: await Crypto.toJWK(await Crypto.toCryptoKey(pubKey)),
                },
            ]),
        ]);

        return response.json({ kid: credential.id });
    }
}
