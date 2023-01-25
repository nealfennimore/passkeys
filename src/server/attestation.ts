import { fromBase64Url, unmarshal, WebAuthnType } from '../utils';
import { Context } from './context';
import * as response from './response';
import * as schema from './schema';

export class Attestation {
    static async generate(ctx: Context) {
        await ctx.setCurrentUserIdForSession(ctx.sessionId, ctx?.body?.userId);
        const challenge = ctx.generateChallenge();
        await ctx.setChallengeForSession(WebAuthnType.Create, challenge);

        return response.json({ challenge }, ctx.headers);
    }

    static async storeCredential(
        ctx: Context,
        payload: schema.Attestation.StoreCredentialPayload
    ) {
        try {
            const { clientDataJSON, kid } = payload;
            const { challenge, type } = unmarshal(
                fromBase64Url(clientDataJSON)
            ) as schema.ClientDataJSON;

            if (type !== WebAuthnType.Create) {
                throw new Error('Wrong credential type');
            }

            const storedChallenge = await ctx.getChallengeForSession(
                WebAuthnType.Create
            );
            if (storedChallenge === null) {
                throw new Error('Must regenerate challenge');
            }

            if (challenge !== storedChallenge) {
                throw new Error('Incorrect challenge');
            }

            const userId = await ctx.getCurrentUserId();
            if (!userId) {
                throw new Error('No user');
            }

            await ctx.DB.batch([
                ctx.createUser(userId),
                ctx.createCredential(payload, userId),
            ]);

            return response.json({
                kid,
            } as schema.Attestation.StoreCredentialResponse);
        } finally {
            await ctx.deleteChallengeForSession(WebAuthnType.Create);
        }
    }
}
