import {
    decode as _fromBase64Url,
    encode as _toBase64Url,
} from '@cfworker/base64url';

const encoder = new TextEncoder();
const decoder = new TextDecoder();
export const encode = encoder.encode.bind(encoder);
export const decode = decoder.decode.bind(decoder);

// From: https://github.com/joaquimserafim/base64-url/blob/master/index.js
export function unescape(str: string) {
    return (str + '==='.slice((str.length + 3) % 4))
        .replace(/-/g, '+')
        .replace(/_/g, '/');
}

// From: https://github.com/joaquimserafim/base64-url/blob/master/index.js
export function escape(str: string) {
    return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export const marshal = JSON.stringify;
export const unmarshal = JSON.parse;

export const toBase64Url = _toBase64Url;
export const fromBase64Url = _fromBase64Url;

export const safeEncode = (data: string) => encode(fromBase64Url(data));
export const safeDecode = (data: ArrayBuffer) => toBase64Url(decode(data));

export function concatBuffer(buffer1: ArrayBuffer, buffer2: ArrayBuffer) {
    let tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
    tmp.set(new Uint8Array(buffer1), 0);
    tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
    return tmp.buffer;
}

export enum WebAuthnType {
    Create = 'webauthn.create',
    Get = 'webauthn.get',
}
