import * as server from './server.js';
import { encode } from './utils.js';

enum COSEAlgorithm {
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
    async function attestation(username: string){
        const { userId, challenge } = await server.API.Attestation.generateUser();
        const abortController = new AbortController();
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

    async function assertion() {
        const challenge = await server.API.Assertion.generateChallengeForCurrentUser();
        const abortController = new AbortController();
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

    document.querySelector('form#attestation')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const data = new FormData(e.target as HTMLFormElement);
        await attestation(data.get('username') as string)
    });
    document.querySelector('form#assertion')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const data = new FormData(e.target as HTMLFormElement);
        await assertion();
    });
}

