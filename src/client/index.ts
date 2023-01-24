import { encode } from '../utils.js';
import * as api from './api';
export enum COSEAlgorithm {
    ES256 = -7,
    ES384 = -35,
    ES512 = -36,
    RS256 = -257,
    RS384 = -258,
    RS512 = -259,
}

if (
    window.PublicKeyCredential // &&
    // (await PublicKeyCredential?.isUserVerifyingPlatformAuthenticatorAvailable?.())
    // && await PublicKeyCredential?.isConditionalMediationAvailable?.())
) {
    async function attestation(
        abortController: AbortController,
        userId: string
    ) {
        const { challenge } = await api.Attestation.generate(userId);
        const publicKey: PublicKeyCredentialCreationOptions = {
            challenge: encode(challenge),
            rp: {
                id: window.location.host,
                name: document.title,
            },
            user: {
                id: encode(userId),
                name: userId,
                displayName: userId,
            },
            pubKeyCredParams: [
                {
                    type: 'public-key',
                    alg: COSEAlgorithm.ES256,
                },
            ],
            authenticatorSelection: {
                userVerification: 'preferred',
                residentKey: 'required',
            },
            attestation: 'indirect',
            timeout: 60_000,
        };

        const credential = (await window.navigator.credentials.create({
            publicKey,
            signal: abortController.signal,
        })) as PublicKeyCredential;
        await api.Attestation.store(credential);
    }

    async function assertion(abortController: AbortController) {
        const { challenge } = await api.Assertion.generate();
        const publicKey: PublicKeyCredentialRequestOptions = {
            challenge: encode(challenge),
            rpId: window.location.host,
            timeout: 60_000,
        };
        const credential = (await window.navigator.credentials.get({
            publicKey,
            signal: abortController.signal,
            mediation: 'optional',
        })) as PublicKeyCredential;
        return await api.Assertion.verify(credential);
    }

    const cancelButton = document.querySelector('button#cancel');

    document
        .querySelector('form#attestation')
        ?.addEventListener('submit', async (e) => {
            e.preventDefault();
            const data = new FormData(e.target as HTMLFormElement);
            const abortController = new AbortController();
            cancelButton?.addEventListener('click', abortController.abort, {
                once: true,
                signal: abortController.signal,
            });
            await attestation(abortController, data.get('username') as string);
            abortController.abort();
        });
    document
        .querySelector('form#assertion')
        ?.addEventListener('submit', async (e) => {
            e.preventDefault();
            const abortController = new AbortController();
            cancelButton?.addEventListener('click', abortController.abort, {
                once: true,
                signal: abortController.signal,
            });
            await assertion(abortController);
            abortController.abort();
        });
}
