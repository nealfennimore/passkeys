import { assertion } from './assertion.js';
import { attestation } from './attestation.js';
import * as dom from './dom.js';

if (
    window.PublicKeyCredential // &&
    // (await PublicKeyCredential?.isUserVerifyingPlatformAuthenticatorAvailable?.())
    // && await PublicKeyCredential?.isConditionalMediationAvailable?.())
) {
    dom.form.addEventListener('submit', (e) => {
        e.preventDefault();
        return false;
    });

    const submit = (fn: CallableFunction) => async (e: Event) => {
        e.preventDefault();
        const data = new FormData(dom.form);
        const abortController = new AbortController();
        const username = data.get('username');
        if (e.target === dom.signupButton && !username) {
            return dom.form.reportValidity();
        }

        const response = await fn(abortController, username);
        if (dom.output) {
            dom.output.value = JSON.stringify(response, undefined, 4);
        }
    };

    dom.signupButton?.addEventListener('click', submit(attestation));
    dom.loginButton?.addEventListener('click', submit(assertion));
}
