import { encode } from '../utils';

export enum WebAuthnType {
    Create = 'webauthn.create',
    Get = 'webauthn.get',
}

export const WebAuthnOrigin = 'https://passkeys.neal.codes';

export const WebAuthnOriginSHA256Hash = crypto.subtle.digest(
    'SHA-256',
    encode(WebAuthnOrigin)
);
