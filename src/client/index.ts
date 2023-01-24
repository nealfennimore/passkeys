import { COSEAlgorithm } from '../crypto.js';
import { encode, safeEncode } from '../utils.js';
import * as api from './api.js';

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
            challenge: safeEncode(challenge),
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
                {
                    type: 'public-key',
                    alg: COSEAlgorithm.ES384,
                },
                {
                    type: 'public-key',
                    alg: COSEAlgorithm.ES512,
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

    async function assertion(abortController: AbortController, userId: string) {
        const { challenge } = await api.Assertion.generate(userId);
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
        .querySelector('form#passkeys button#signup')
        ?.addEventListener('click', async (e) => {
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
        .querySelector('form#passkeys button#login')
        ?.addEventListener('click', async (e) => {
            e.preventDefault();
            const data = new FormData(e.target as HTMLFormElement);
            const abortController = new AbortController();
            cancelButton?.addEventListener('click', abortController.abort, {
                once: true,
                signal: abortController.signal,
            });
            await assertion(abortController, data.get('username') as string);
            abortController.abort();
        });
}
