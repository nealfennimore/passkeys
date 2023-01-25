import { safeByteEncode } from '../../utils';
import { Env } from '../env';
import * as schema from '../schema';

export interface DBCredential {
    kid: string;
    pubkey: Array<number>;
    attestation_data: Array<number>;
    userId: string;
}

export interface StoredCredential {
    kid: string;
    pubkey: ArrayBuffer;
    attestationData: ArrayBuffer;
    userId: string;
}

export interface AttestationStatement {
    alg: number;
    sig: ArrayBuffer;
    x5c: Array<ArrayBuffer>;
}

export interface CborAttestation {
    attStmt: AttestationStatement;
    authData: ArrayBuffer;
    fmt: string;
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

    createCredential(
        payload: schema.Attestation.StoreCredentialPayload,
        userId: string
    ) {
        const { kid, pubkey, attestationObject } = payload;

        return this.D1.prepare(
            'INSERT INTO public_keys(kid, pubkey, attestation_data, user_id) VALUES(?1, ?2, ?3, ?4)'
        ).bind(
            kid,
            safeByteEncode(pubkey),
            safeByteEncode(attestationObject),
            userId
        );
    }

    async getCredentialByKid(kid: string) {
        const { pubkey, userId, attestation_data } = (await this.D1.prepare(
            'SELECT kid, pubkey, user_id as userId, attestation_data FROM public_keys WHERE kid = ?'
        )
            .bind(kid)
            .first()) as DBCredential;

        return {
            kid,
            pubkey: Uint8Array.from(pubkey).buffer,
            attestationData: Uint8Array.from(attestation_data).buffer,
            userId,
        } as StoredCredential | null;
    }
}
