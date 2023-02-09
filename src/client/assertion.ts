import { safeEncode } from '../utils.js';
import * as api from './api.js';

export async function assertion(abortController: AbortController) {
    const { challenge } = await api.Assertion.generate();
    const publicKey: PublicKeyCredentialRequestOptions = {
        challenge: safeEncode(challenge),
        rpId: window.location.host,
        timeout: 60_000,
    };

    const mediation =
        /*
         * Optional fills the need in most cases, but we can use conditional if wanted
         * https://w3c.github.io/webappsec-credential-management/#dom-credentialmediationrequirement-conditional
         */
        // @ts-ignore
        (await PublicKeyCredential?.isConditionalMediationAvailable?.())
            ? 'conditional'
            : 'optional';

    const credential = (await window.navigator.credentials.get({
        publicKey,
        signal: abortController.signal,
        mediation: mediation as CredentialMediationRequirement,
    })) as PublicKeyCredential;
    return await api.Assertion.verify(credential);
}
