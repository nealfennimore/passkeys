export enum Digests {
    SHA256 = 'SHA-256',
    SHA384 = 'SHA-384',
    SHA512 = 'SHA-512',
}

export enum SigningAlg {
    ECDSA = 'ECDSA',
}

export enum COSEAlgorithm {
    ES256 = -7,
    ES384 = -35,
    ES512 = -36,
    // RS256 = -257,
    // RS384 = -258,
    // RS512 = -259,
}

export enum SigningCurve {
    P256 = 'P-256',
    P384 = 'P-384',
    P512 = 'P-512',
}

export enum JwkAlg {
    ES256 = 'ES256',
    ES384 = 'ES384',
    ES512 = 'ES512',
}

export const JwkAlgToSigningCurve = {
    [JwkAlg.ES256]: SigningCurve.P256,
    [JwkAlg.ES384]: SigningCurve.P384,
    [JwkAlg.ES512]: SigningCurve.P512,
};

export const JwkAlgToSigningAlg = {
    [JwkAlg.ES256]: SigningAlg.ECDSA,
    [JwkAlg.ES384]: SigningAlg.ECDSA,
    [JwkAlg.ES512]: SigningAlg.ECDSA,
};
export const JwkAlgToDigest = {
    [JwkAlg.ES256]: Digests.SHA256,
    [JwkAlg.ES384]: Digests.SHA384,
    [JwkAlg.ES512]: Digests.SHA512,
};

export const COSEAlgToSigningCurve = {
    [COSEAlgorithm.ES256.toString()]: SigningCurve.P256,
    [COSEAlgorithm.ES384.toString()]: SigningCurve.P384,
    [COSEAlgorithm.ES512.toString()]: SigningCurve.P512,
};

export const COSEAlgToSigningAlg = {
    [COSEAlgorithm.ES256.toString()]: SigningAlg.ECDSA,
    [COSEAlgorithm.ES384.toString()]: SigningAlg.ECDSA,
    [COSEAlgorithm.ES512.toString()]: SigningAlg.ECDSA,
};

export class Crypto {
    static async toCryptoKey(
        pubKey: ArrayBuffer,
        name: SigningAlg,
        namedCurve: SigningCurve
    ) {
        return await crypto.subtle.importKey(
            'spki',
            pubKey,
            { name, namedCurve },
            true,
            ['verify']
        );
    }

    static async toJWK(pubKey: CryptoKey) {
        return await crypto.subtle.exportKey('jwk', pubKey);
    }
    static async fromJWK(jwk: JsonWebKey) {
        const name = JwkAlgToSigningAlg[jwk.alg as JwkAlg];
        const namedCurve = JwkAlgToSigningCurve[jwk.alg as JwkAlg];
        return await crypto.subtle.importKey(
            'jwk',
            jwk,
            { name, namedCurve },
            true,
            ['verify']
        );
    }
}
