export declare enum Digests {
    SHA256 = "SHA-256"
}
export declare enum SigningAlg {
    ECDSA = "ECDSA"
}
export declare enum SigningCurve {
    P256 = "P-256"
}
export declare class Crypto {
    static toCryptoKey(pubKey: ArrayBuffer): Promise<CryptoKey>;
    static toJWK(pubKey: CryptoKey): Promise<JsonWebKey>;
    static fromJWK(jwk: JsonWebKey): Promise<CryptoKey>;
}
