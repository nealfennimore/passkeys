import { decode, marshal, WebAuthnType } from "../../utils.js";
import { Context } from '../context.js';
import { Crypto } from '../crypto.js';

export class Attestation {
    static async generateUser(ctx: Context, userId: string){
        const sessionId = crypto.randomUUID();
        const challenge = await ctx.generateChallenge();

        await Promise.all([
            ctx.setChallenge(WebAuthnType.Create, challenge),
            ctx.setCurrentUserId(sessionId, userId)
        ]);
        
        return new Response(marshal({challenge}), {
            headers: {
                'Set-Cookie': `session_id=${sessionId}; Path=/; HttpOnly;`,
                'content-type': 'application/json;charset=UTF-8',
            }
        });
    }
    
    static async storeCredential(ctx: Context, credential: PublicKeyCredential) {
        const response = credential.response as AuthenticatorAttestationResponse;
        const { clientDataJSON } = response;
        const pubKey = response.getPublicKey() as ArrayBuffer;

        const { challenge, type } = JSON.parse(decode(clientDataJSON))

        if (type !== WebAuthnType.Create) {
            throw new Error("Wrong credential type")
        }

        const storedChallenge = ctx.getChallenge(type);
        
        if (storedChallenge !== null && challenge !== storedChallenge){
            throw new Error("Incorrect challenge");
        }

        await Promise.all([
            ctx.setChallenge(WebAuthnType.Create, null),
            ctx.setCredentials(
                [{
                    kid: credential.id,
                    jwk: await Crypto.toJWK(await Crypto.toCryptoKey(pubKey))
                }]
            )
        ])

        return new Response();
    }
}
