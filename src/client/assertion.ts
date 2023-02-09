import { safeEncode } from '../utils.js';
import * as api from './api.js';

export async function assertion(abortController: AbortController) {
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
