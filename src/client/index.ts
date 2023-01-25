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
        username: string
    ) {
        const userId = crypto.randomUUID();
        const { challenge } = await api.Attestation.generate(userId);
        const publicKey: PublicKeyCredentialCreationOptions = {
            challenge: safeEncode(challenge),
            rp: {
                id: window.location.host,
                name: document.title,
            },
            user: {
                id: encode(userId),
                name: username,
                displayName: '',
            },
            pubKeyCredParams: [
                {
                    type: 'public-key',
                    alg: COSEAlgorithm.ES512,
                },
                {
                    type: 'public-key',
                    alg: COSEAlgorithm.ES384,
                },
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
        return await api.Attestation.store(credential);
    }

    async function assertion(abortController: AbortController) {
        const { challenge } = await api.Assertion.generate();
        const publicKey: PublicKeyCredentialRequestOptions = {
            challenge: safeEncode(challenge),
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
    const output = document.querySelector(
        'textarea#output'
    ) as HTMLTextAreaElement;

    const submit = (fn: CallableFunction) => async (e: Event) => {
        e.preventDefault();
        const data = new FormData(
            document.querySelector('form#passkeys') as HTMLFormElement
        );
        const abortController = new AbortController();
        cancelButton?.addEventListener('click', abortController.abort, {
            once: true,
            signal: abortController.signal,
        });
        const response = await fn(
            abortController,
            data.get('username') as string
        );
        if (output) {
            output.value = JSON.stringify(response, undefined, 4);
        }
        abortController.abort();
    };

    document
        .querySelector('form#passkeys button#signup')
        ?.addEventListener('click', submit(attestation));

    document
        .querySelector('form#passkeys button#login')
        ?.addEventListener('click', submit(assertion));
}
