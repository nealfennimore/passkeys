type ChallengeResponseShared = {
    challenge: string;
};
export type ClientDataJSON = {
    type: string;
    challenge: string;
    origin: string;
    crossOrigin: boolean;
};
export declare namespace Attestation {
    type ChallengePayload = {
        userId: string;
    };
    type ChallengeResponse = ChallengeResponseShared;
    type StoreCredentialPayload = {
        kid: string;
        clientDataJSON: string;
        attestationObject: string;
        jwk: JsonWebKey;
    };
    type StoreCredentialResponse = {
        kid: string;
    };
}
export declare namespace Assertion {
    type ChallengeResponse = ChallengeResponseShared;
    type VerifyPayload = {
        kid: string;
        clientDataJSON: string;
        authenticatorData: string;
        signature: string;
    };
    type VerifyResponse = {
        isVerified: boolean;
    };
}
export {};
