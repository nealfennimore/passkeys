import { COSEAlgorithm } from '../crypto.js';
import { encode, safeDecode } from '../utils.js';
import * as api from './api.js';

export async function attestation(
    abortController: AbortController,
    username: string
) {
    const userId = crypto.randomUUID();
    const { challenge } = await api.Attestation.generate(userId);
    const publicKey: PublicKeyCredentialCreationOptions = {
        challenge: safeDecode(challenge),
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
