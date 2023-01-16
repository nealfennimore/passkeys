import * as server from '../server/index.js';
import { encode } from '../utils.js';
export var COSEAlgorithm;
(function (COSEAlgorithm) {
    COSEAlgorithm[COSEAlgorithm["ES256"] = -7] = "ES256";
    COSEAlgorithm[COSEAlgorithm["ES384"] = -35] = "ES384";
    COSEAlgorithm[COSEAlgorithm["ES512"] = -36] = "ES512";
    COSEAlgorithm[COSEAlgorithm["RS256"] = -257] = "RS256";
    COSEAlgorithm[COSEAlgorithm["RS384"] = -258] = "RS384";
    COSEAlgorithm[COSEAlgorithm["RS512"] = -259] = "RS512";
})(COSEAlgorithm || (COSEAlgorithm = {}));
if (window.PublicKeyCredential
    && await PublicKeyCredential?.isUserVerifyingPlatformAuthenticatorAvailable?.()) {
    async function attestation(abortController, username) {
        const { userId, challenge } = await server.API.Attestation.generateUser();
        const publicKey = {
            challenge: encode(challenge),
            rp: {
                id: window.location.host,
                name: document.title,
            },
            user: {
                id: encode(userId),
                name: username,
                displayName: username,
            },
            pubKeyCredParams: [{
                    type: "public-key",
                    alg: COSEAlgorithm.ES256,
                }],
            authenticatorSelection: {
                authenticatorAttachment: 'platform',
                userVerification: 'preferred',
                requireResidentKey: true,
            },
            attestation: 'indirect',
            timeout: 60000,
        };
        const credential = await window.navigator.credentials.create({
            publicKey,
            signal: abortController.signal,
        });
        await server.API.Attestation.storeCredential(credential);
    }
    async function assertion(abortController) {
        const challenge = await server.API.Assertion.generateChallengeForCurrentUser();
        const publicKey = {
            challenge: encode(challenge),
            rpId: window.location.host,
            timeout: 60000,
        };
        const credential = await window.navigator.credentials.get({
            publicKey,
            signal: abortController.signal,
            mediation: 'optional',
        });
        await server.API.Assertion.verifyCredential(credential);
    }
    const cancelButton = document.querySelector('button#cancel');
    document.querySelector('form#attestation')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const data = new FormData(e.target);
        const abortController = new AbortController();
        cancelButton?.addEventListener('click', abortController.abort, { once: true, signal: abortController.signal });
        await attestation(abortController, data.get('username'));
        abortController.abort();
    });
    document.querySelector('form#assertion')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const abortController = new AbortController();
        cancelButton?.addEventListener('click', abortController.abort, { once: true, signal: abortController.signal });
        await assertion(abortController);
        abortController.abort();
    });
}
//# sourceMappingURL=index.js.map