export enum Digests {
    SHA256 = 'SHA-256',
}

export enum SigningAlg {
    ECDSA = 'ECDSA',
}

export enum SigningCurve {
    P256 = 'P-256',
}

export class Crypto {
    static async toCryptoKey(pubKey: ArrayBuffer) {
        return await crypto.subtle.importKey(
            'spki',
            pubKey,
            { name: SigningAlg.ECDSA, namedCurve: SigningCurve.P256 },
            true,
            ['verify']
        );
    }

    static async toJWK(pubKey: CryptoKey) {
        return await crypto.subtle.exportKey('jwk', pubKey);
    }
    static async fromJWK(jwk: JsonWebKey) {
        return await crypto.subtle.importKey(
            'jwk',
            jwk,
            { name: SigningAlg.ECDSA, namedCurve: SigningCurve.P256 },
            true,
            ['verify']
        );
    }
}
