import { fromBase64Url, unmarshal, WebAuthnType } from '../utils';
import { Context } from './context';
import * as response from './response';
import * as schema from './schema';

export class Attestation {
    static async generate(ctx: Context) {
        const challenge = ctx.generateChallenge();
        await ctx.setChallenge(WebAuthnType.Create, challenge);

        return response.json({ challenge }, ctx.headers);
    }

    static async storeCredential(
        ctx: Context,
        payload: schema.Attestation.StoreCredentialPayload
    ) {
        try {
            const { clientDataJSON, kid, jwk } = payload;
            const { challenge, type } = unmarshal(
                fromBase64Url(clientDataJSON)
            ) as schema.ClientDataJSON;

            if (type !== WebAuthnType.Create) {
                throw new Error('Wrong credential type');
            }

            const storedChallenge = await ctx.getChallenge(WebAuthnType.Create);
            if (storedChallenge === null) {
                throw new Error('Must regenerate challenge');
            }

            if (fromBase64Url(challenge) !== storedChallenge) {
                throw new Error('Incorrect challenge');
            }

            await ctx.setCredentials([
                {
                    kid,
                    jwk,
                },
            ]);

            const data = {
                kid,
            } as schema.Attestation.StoreCredentialResponse;
            return response.json(data);
        } finally {
            ctx.deleteChallenge(WebAuthnType.Create);
        }
    }
}
