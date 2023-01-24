import { Crypto } from '../crypto';
import { decode, safeDecode, unmarshal } from '../utils';
const makeRequest = (endpoint, data = {}) => fetch(new Request(`https://api.passkeys.workers.dev/${endpoint}`, {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify(data),
    credentials: 'include',
}));
export var Attestation;
(function (Attestation) {
    async function generate(userId) {
        const response = await makeRequest('attestation/generate', {
            userId,
        });
        return (await response.json());
    }
    Attestation.generate = generate;
    async function store(credential) {
        const attestation = credential.response;
        const payload = {
            kid: safeDecode(credential.rawId),
            clientDataJSON: unmarshal(decode(attestation.clientDataJSON)),
            attestationObject: safeDecode(attestation.attestationObject),
            jwk: await Crypto.toJWK(await Crypto.toCryptoKey(attestation.getPublicKey())),
        };
        const response = await makeRequest('attestation/store', payload);
        return (await response.json());
    }
    Attestation.store = store;
})(Attestation || (Attestation = {}));
export var Assertion;
(function (Assertion) {
    async function generate() {
        const response = await makeRequest('assertion/generate');
        return (await response.json());
    }
    Assertion.generate = generate;
    async function verify(credential) {
        const assertion = credential.response;
        const payload = {
            kid: safeDecode(credential.rawId),
            clientDataJSON: unmarshal(decode(assertion.clientDataJSON)),
            authenticatorData: safeDecode(assertion.authenticatorData),
            signature: safeDecode(assertion.signature),
        };
        const response = await makeRequest('assertion/verify', payload);
        return (await response.json());
    }
    Assertion.verify = verify;
})(Assertion || (Assertion = {}));
//# sourceMappingURL=api.js.map