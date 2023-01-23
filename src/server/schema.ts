type ChallengeResponseShared = {
    challenge: string;
};

export namespace Attestation {
    export type ChallengePayload = {
        userId: string;
    };

    export type ChallengeResponse = ChallengeResponseShared;

    export type StoreCredentialPayload = {
        kid: string;
        clientDataJSON: string;
        attestationObject: string;
        jwk: JsonWebKey;
    };

    export type StoreCredentialResponse = {
        kid: string;
    };
}

export namespace Assertion {
    export type ChallengeResponse = ChallengeResponseShared;

    export type VerifyPayload = {
        kid: string;
        clientDataJSON: string;
        authenticatorData: string;
        signature: string;
    };
    export type VerifyResponse = {
        isVerified: boolean;
    };
}
