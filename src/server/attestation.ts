import { fromBase64Url, unmarshal, WebAuthnType } from '../utils';
import { Context } from './context';
import * as response from './response';
import * as schema from './schema';

export class Attestation {
    static async generate(ctx: Context, userId: string) {
        const sessionId = ctx.sessionId;
        let headers;
        if (!ctx.hasSession) {
            await ctx.setCurrentUserId(sessionId, userId);
            headers = {
                'Set-Cookie': `session_id=${sessionId}; Path=/; HttpOnly; SameSite=None; Secure;`,
            };
        }

        const challenge = ctx.generateChallenge();
        await ctx.setChallenge(WebAuthnType.Create, challenge);

        return response.json({ challenge }, headers);
    }

    static async storeCredential(
        ctx: Context,
        payload: schema.Attestation.StoreCredentialPayload
    ) {
        const { clientDataJSON, kid, jwk } = payload;
        const { challenge, type } = unmarshal(
            fromBase64Url(clientDataJSON)
        ) as schema.ClientDataJSON;

        if (type !== WebAuthnType.Create) {
            throw new Error('Wrong credential type');
        }

        const storedChallenge = await ctx.getChallenge(WebAuthnType.Create);

        if (
            storedChallenge === null ||
            fromBase64Url(challenge) !== storedChallenge
        ) {
            throw new Error('Incorrect challenge');
        }

        await Promise.all([
            ctx.deleteChallenge(WebAuthnType.Create),
            ctx.setCredentials([
                {
                    kid,
                    jwk,
                },
            ]),
        ]);
        const data = {
            kid,
        } as schema.Attestation.StoreCredentialResponse;
        return response.json(data);
    }
}
