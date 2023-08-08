import { byteStringToBuffer, concatBuffer } from './utils';

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

export const COSEAlgToDigest = {
    [COSEAlgorithm.ES256.toString()]: Digests.SHA256,
    [COSEAlgorithm.ES384.toString()]: Digests.SHA384,
    [COSEAlgorithm.ES512.toString()]: Digests.SHA512,
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

export const stringTimingSafeEqual = (a: string, b: string): boolean => {
    // @ts-ignore
    return crypto.subtle.timingSafeEqual(
        byteStringToBuffer(a),
        byteStringToBuffer(b)
    );
};

export function fromAsn1DERtoRSSignature(
    signature: ArrayBuffer,
    hashBitLength: number
) {
    const sig = new Uint8Array(signature);

    const rStart = 4;
    const rLength = sig[3];
    const sStart = rStart + rLength + 2;
    const sLength = sig[rStart + rLength + 1];

    const r = sig.slice(rStart, rStart + rLength);
    const s = sig.slice(sStart, sStart + sLength);

    if (hashBitLength % 8 !== 0) {
        throw new Error(
            `hashBitLength ${hashBitLength} is not a multiple of 8`
        );
    }

    const padding = hashBitLength / 8;

    if (r.length > padding || s.length > padding) {
        throw new Error(
            `Invalid r or s value bigger than allowed max size of ${padding}`
        );
    }

    const rPadding = padding - r.length;
    const sPadding = padding - s.length;

    return concatBuffer(
        new Uint8Array(rPadding).fill(0),
        r,
        new Uint8Array(sPadding).fill(0),
        s
    );
}

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
}
