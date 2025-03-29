import { safeByteEncode } from '../../utils';
import { Env } from '../env';
import * as schema from '../schema';

export interface DBCredential {
    kid: string;
    pubkey: Array<number>;
    userId: string;
    coseAlg: number;
    signCounter: Array<number> | null;
}

export interface StoredCredential {
    kid: string;
    pubkey: ArrayBuffer;
    userId: string;
    coseAlg: number;
    signCounter: ArrayBuffer | null;
}

export interface DBUser {
    id: string;
}

export class DB {
    private env: Env;

    constructor(env: Env) {
        this.env = env;
    }

    get D1() {
        return this.env.DB;
    }

    createUser(userId: string) {
        return this.D1.prepare('INSERT INTO users(id) VALUES(?)').bind(userId);
    }

    async hasUser(userId: string) {
        const user = (await this.D1.prepare(
            'SELECT id FROM users WHERE id = ? LIMIT 1'
        )
            .bind(userId)
            .first()) as DBUser | null;

        return user?.id === userId;
    }

    createCredential(
        payload: schema.Attestation.StoreCredentialPayload,
        userId: string
    ) {
        const { kid, pubkey, attestationObject, coseAlg } = payload;

        return this.D1.prepare(
            'INSERT INTO public_keys(kid, pubkey, attestation_data, cose_alg, user_id) VALUES(?1, ?2, ?3, ?4, ?5)'
        ).bind(
            kid,
            safeByteEncode(pubkey),
            safeByteEncode(attestationObject),
            coseAlg,
            userId
        );
    }

    async updateCredentialSigningCounter(
        kid: string,
        signCounter: ArrayBuffer
    ) {
        return await this.D1.prepare(
            'UPDATE public_keys SET sign_counter = ?1 WHERE kid = ?2'
        )
            .bind(signCounter, kid)
            .run();
    }

    async getCredentialByKid(kid: string) {
        const { pubkey, coseAlg, userId, signCounter } = (await this.D1.prepare(
            'SELECT kid, pubkey, cose_alg as coseAlg, user_id as userId, sign_counter as signCounter FROM public_keys WHERE kid = ?'
        )
            .bind(kid)
            .first()) as DBCredential;

        return {
            kid,
            pubkey: Uint8Array.from(pubkey).buffer,
            coseAlg,
            userId,
            signCounter: signCounter
                ? Uint8Array.from(signCounter).buffer
                : null,
        } as StoredCredential | null;
    }
}
