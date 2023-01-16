export var Digests;
(function (Digests) {
    Digests["SHA256"] = "SHA-256";
})(Digests || (Digests = {}));
export var SigningAlg;
(function (SigningAlg) {
    SigningAlg["ECDSA"] = "ECDSA";
})(SigningAlg || (SigningAlg = {}));
export var SigningCurve;
(function (SigningCurve) {
    SigningCurve["P256"] = "P-256";
})(SigningCurve || (SigningCurve = {}));
export class Crypto {
    static async toCryptoKey(pubKey) {
        return await crypto.subtle.importKey('spki', pubKey, { name: SigningAlg.ECDSA, namedCurve: SigningCurve.P256 }, true, ['verify']);
    }
    static async toJWK(pubKey) {
        return await crypto.subtle.exportKey('jwk', pubKey);
    }
    static async fromJWK(jwk) {
        return await crypto.subtle.importKey('jwk', jwk, { name: SigningAlg.ECDSA, namedCurve: SigningCurve.P256 }, true, ['verify']);
    }
}
//# sourceMappingURL=crypto.js.map