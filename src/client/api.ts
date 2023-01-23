import { Crypto } from '../crypto';
import * as schema from '../server/schema';
import { safeDecode } from '../utils';

const makeRequest = (endpoint: string, data: object = {}) =>
    fetch(
        new Request(`https://api.passkeys.workers.dev/${endpoint}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data),
            credentials: 'include',
        })
    );

export namespace Attestation {
    export async function generate(userId: string) {
        const response = await makeRequest('attestation/generate', {
            userId,
        } as schema.Attestation.ChallengePayload);
        return (await response.json()) as schema.Attestation.ChallengeResponse;
    }

    export async function store(credential: PublicKeyCredential) {
        const attestation =
            credential.response as AuthenticatorAttestationResponse;

        const payload: schema.Attestation.StoreCredentialPayload = {
            kid: safeDecode(credential.rawId),
            clientDataJSON: safeDecode(attestation.clientDataJSON),
            attestationObject: safeDecode(attestation.attestationObject),
            jwk: await Crypto.toJWK(
                await Crypto.toCryptoKey(
                    attestation.getPublicKey() as ArrayBuffer
                )
            ),
        };

        const response = await makeRequest('attestation/store', payload);
        return (await response.json()) as schema.Attestation.StoreCredentialResponse;
    }
}

export namespace Assertion {
    export async function generate() {
        const response = await makeRequest('assertion/generate');
        return (await response.json()) as schema.Assertion.ChallengeResponse;
    }

    export async function verify(credential: PublicKeyCredential) {
        const assertion = credential.response as AuthenticatorAssertionResponse;
        const payload: schema.Assertion.VerifyPayload = {
            kid: safeDecode(credential.rawId),
            clientDataJSON: safeDecode(assertion.clientDataJSON),
            authenticatorData: safeDecode(assertion.authenticatorData),
            signature: safeDecode(assertion.signature),
        };
        const response = await makeRequest('assertion/verify', payload);
        return (await response.json()) as schema.Assertion.VerifyResponse;
    }
}
