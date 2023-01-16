import { decode } from "../utils.js";
import { Cache, Context, UserCredentialCache } from './context.js';
import { Crypto } from './crypto.js';


export class Attestation {
    static async generateUser(){
        const userId = window.crypto.randomUUID();
        const challenge = await Context.generateChallenge();
        const credentials: UserCredentialCache = {
            userId,
            challenge,
        };
        Cache.store('currentUserId', userId);
        Cache.store(userId, credentials);
        return credentials;
    }
    
    static async storeCredential(credential: PublicKeyCredential) {
        const response = credential.response as AuthenticatorAttestationResponse;
        const { clientDataJSON } = response;
        const pubKey = response.getPublicKey() as ArrayBuffer;

        const { challenge, type } = JSON.parse(decode(clientDataJSON))

        if (type !== 'webauthn.create') {
            throw new Error("Wrong credential type")
        }

        const currentCredentials = await Context.getCredentials();
        const { credentials = [], challenge: storedChallenge } = currentCredentials;
        
        if (challenge !== storedChallenge){
            throw new Error("Incorrect challenge");
        }
        
        Cache.store(currentCredentials.userId, {
            ...currentCredentials,
            credentials: [
                ...credentials,
                // @ts-ignore
                {
                    kid: credential.id,
                    jwk: await Crypto.toJWK(await Crypto.toCryptoKey(pubKey))
                }
                
            ]
        });
    }
}
