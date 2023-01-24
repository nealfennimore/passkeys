import { fromBase64Url, unmarshal, WebAuthnType } from '../utils';
import * as response from './response';
export class Attestation {
    static async generate(ctx, userId) {
        const sessionId = ctx.sessionId;
        if (!ctx.hasSession) {
            await ctx.setCurrentUserId(sessionId, userId);
        }
        const challenge = ctx.generateChallenge();
        await ctx.setChallenge(WebAuthnType.Create, challenge);
        return response.json({ challenge }, {
            'Set-Cookie': `session_id=${sessionId}; Path=/; HttpOnly; SameSite=None; Secure;`,
        });
    }
    static async storeCredential(ctx, payload) {
        const { clientDataJSON, kid, jwk } = payload;
        const { challenge, type } = unmarshal(fromBase64Url(clientDataJSON));
        if (type !== WebAuthnType.Create) {
            throw new Error('Wrong credential type');
        }
        const storedChallenge = await ctx.getChallenge(WebAuthnType.Create);
        if (storedChallenge === null || challenge !== storedChallenge) {
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
        };
        return response.json(data);
    }
}
//# sourceMappingURL=attestation.js.map