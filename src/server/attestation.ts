import * as x509 from '@peculiar/x509';
import {
    COSEAlgToDigest,
    COSEAlgToDigestBits,
    fromAsn1DERtoRSSignature,
    stringTimingSafeEqual,
} from '../crypto';
import {
    cborDecode,
    concatBuffer,
    isEqualBuffer,
    safeByteEncode,
    unmarshal,
} from '../utils';
import { HostDigest, Origin, WebAuthnType } from './constants';
import { Context } from './context';
import * as response from './response';
import * as schema from './schema';

x509.cryptoProvider.set(crypto as Crypto);

export class Attestation {
    static async generate(ctx: Context) {
        const body = await ctx?.request?.body();
        await ctx.cache.setCurrentUserIdForSession(
            ctx.cache.sessionId,
            body?.userId
        );
        const challenge = ctx.generateChallenge();
        await ctx.cache.setChallengeForSession(WebAuthnType.Create, challenge);

        return response.json({ challenge }, ctx.response.headers);
    }

    static async storeCredential(
        ctx: Context,
        payload: schema.Attestation.StoreCredentialPayload
    ) {
        try {
            const { clientDataJSON, attestationObject, kid, coseAlg } = payload;
            const { challenge, type, origin } = unmarshal(
                clientDataJSON
            ) as schema.ClientDataJSON;

            const { authData, attStmt } = cborDecode(
                new Uint8Array(safeByteEncode(attestationObject))
            );

            if (attStmt.hasOwnProperty('ecdaaKeyId')) {
                throw new Error('Not supporting ecdaaKeyId');
            }

            if (type !== WebAuthnType.Create) {
                throw new Error('Wrong credential type');
            }

            // Support hardware tokens like yubikeys
            if (attStmt.hasOwnProperty('x5c')) {
                const clientDataHash = await crypto.subtle.digest(
                    'SHA-256',
                    safeByteEncode(clientDataJSON)
                );
                const cert = new x509.X509Certificate(attStmt.x5c[0]);
                const pubkey = await cert.publicKey.export();
                const signatureBase = concatBuffer(authData, clientDataHash);

                if (
                    !(await crypto.subtle.verify(
                        { name: 'ECDSA', hash: COSEAlgToDigest[coseAlg] },
                        pubkey,
                        fromAsn1DERtoRSSignature(
                            attStmt.sig,
                            COSEAlgToDigestBits[coseAlg]
                        ),
                        signatureBase
                    ))
                ) {
                    throw new Error('Invalid x5c signature');
                }
            }

            const rpIdHash = authData.slice(0, 32).buffer;
            if (
                origin !== Origin ||
                !isEqualBuffer(rpIdHash, await HostDigest)
            ) {
                throw new Error('Key generated from wrong origin');
            }

            const storedChallenge = await ctx.cache.getChallengeForSession(
                WebAuthnType.Create
            );
            if (storedChallenge === null) {
                throw new Error('Must regenerate challenge');
            }

            if (!stringTimingSafeEqual(challenge, storedChallenge)) {
                throw new Error('Incorrect challenge');
            }

            const userId = await ctx.cache.getCurrentUserId();
            if (!userId) {
                throw new Error('No user');
            }

            await ctx.db.D1.batch([
                ctx.db.createUser(userId),
                ctx.db.createCredential(payload, userId),
            ]);

            return response.json({
                kid,
            } as schema.Attestation.StoreCredentialResponse);
        } finally {
            await ctx.cache.deleteChallengeForSession(WebAuthnType.Create);
        }
    }
}
