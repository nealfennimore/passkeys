import * as server from '../server/index.js';
import { encode } from '../utils.js';

export enum COSEAlgorithm {
    ES256 = -7,
    ES384 = -35,
    ES512 = -36,
    RS256 = -257,
    RS384 = -258,
    RS512 = -259,
}

if (window.PublicKeyCredential  
    && await PublicKeyCredential?.isUserVerifyingPlatformAuthenticatorAvailable?.() 
    // && await PublicKeyCredential?.isConditionalMediationAvailable?.())
){
    async function attestation(abortController: AbortController, username: string){
        const { userId, challenge } = await server.API.Attestation.generateUser();
        const publicKey: PublicKeyCredentialCreationOptions = {
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
            timeout: 60_000,
        };
        
        const credential = await window.navigator.credentials.create({
            publicKey,
            signal: abortController.signal,
        }) as PublicKeyCredential;
        await server.API.Attestation.storeCredential(credential);
    }

    async function assertion(abortController: AbortController) {
        const challenge = await server.API.Assertion.generateChallengeForCurrentUser();
        const publicKey: PublicKeyCredentialRequestOptions = {
            challenge: encode(challenge),
            rpId: window.location.host,
            timeout: 60_000,
        };
        const credential = await window.navigator.credentials.get({
            publicKey,
            signal: abortController.signal,
            mediation: 'optional',
        }) as PublicKeyCredential;
        await server.API.Assertion.verifyCredential(credential);
    }

    const cancelButton = document.querySelector('button#cancel');

    document.querySelector('form#attestation')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const data = new FormData(e.target as HTMLFormElement);
        const abortController = new AbortController();
        cancelButton?.addEventListener('click', abortController.abort, { once: true, signal: abortController.signal});
        await attestation(abortController, data.get('username') as string)
        abortController.abort();
    });
    document.querySelector('form#assertion')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const abortController = new AbortController();
        cancelButton?.addEventListener('click', abortController.abort, { once: true, signal: abortController.signal});
        await assertion(abortController);
        abortController.abort();
    });
}

