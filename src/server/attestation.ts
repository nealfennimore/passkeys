import * as x509 from '@peculiar/x509';
import {
    COSEAlgToDigest,
    COSEAlgToDigestBits,
    COSEAlgToSigningAlg,
    COSEAlgToSigningCurve,
    Crypto as _Crypto,
    fromAsn1DERtoRSSignature,
    stringTimingSafeEqual,
} from '../crypto';
import {
    cborDecode,
    concatBuffer,
    isEqualBuffer,
    safeByteDecode,
    unmarshal,
} from '../utils';
import { HostDigest, Origin, WebAuthnType } from './constants';
import { Context } from './context';
import * as response from './response';
import * as schema from './schema';

x509.cryptoProvider.set(crypto as Crypto);

enum DecodedAttestationObjectFormat {
    none = 'none',
    packed = 'packed',
}
type DecodedAttestationObjectAttStmt = {
    x5c?: Uint8Array[];
    sig?: Uint8Array;
};

type DecodedAttestationObject = {
    fmt: DecodedAttestationObjectFormat;
    authData: Uint8Array;
    attStmt: DecodedAttestationObjectAttStmt;
};

async function validatePacked(
    attStmt: DecodedAttestationObjectAttStmt,
    authData: Uint8Array,
    payload: schema.Attestation.StoreCredentialPayload
) {
    if (!attStmt?.sig) {
        throw new Error('No attestation signature');
    }
    let pubkey: CryptoKey;
    if (attStmt.hasOwnProperty('x5c')) {
        if (!attStmt?.x5c?.length) {
            throw new Error('No x509 certs');
        }
        const cert = new x509.X509Certificate(attStmt.x5c[0]);
        pubkey = await cert.publicKey.export();
    } else {
        pubkey = await _Crypto.toCryptoKey(
            safeByteDecode(payload.pubkey),
            COSEAlgToSigningAlg[payload.coseAlg],
            COSEAlgToSigningCurve[payload.coseAlg]
        );
    }
    const clientDataHash = await crypto.subtle.digest(
        'SHA-256',
        safeByteDecode(payload.clientDataJSON)
    );
    const signatureBase = concatBuffer(authData, clientDataHash);
    const isVerified = await crypto.subtle.verify(
        { name: 'ECDSA', hash: COSEAlgToDigest[payload.coseAlg] },
        pubkey,
        fromAsn1DERtoRSSignature(
            attStmt.sig,
            COSEAlgToDigestBits[payload.coseAlg]
        ),
        signatureBase
    );

    if (!isVerified) {
        throw new Error('Invalid x5c signature');
    }
}

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
            const { clientDataJSON, attestationObject, kid } = payload;
            const { challenge, type, origin } = unmarshal(
                clientDataJSON
            ) as schema.ClientDataJSON;

            if (type !== WebAuthnType.Create) {
                throw new Error('Wrong credential type');
            }

            const { fmt, authData, attStmt }: DecodedAttestationObject =
                cborDecode(new Uint8Array(safeByteDecode(attestationObject)));

            switch (fmt) {
                case 'none':
                    // Nothing to do here
                    break;
                case 'packed':
                    await validatePacked(attStmt, authData, payload);
                    break;
                default:
                    throw new Error(`Unsupported attestation format: ${fmt}`);
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
