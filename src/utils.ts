import base64url from "base64url";

export const encode = new TextEncoder().encode;
export const decode = new TextDecoder().decode;

export const toBase64Url = base64url.encode;
export const fromBase64Url = base64url.decode;

export const safeEncode = (data: string) => encode(fromBase64Url(data));
export const safeDecode = (data: ArrayBuffer) => toBase64Url(decode(data));

export function concatBuffer(buffer1: ArrayBuffer, buffer2: ArrayBuffer) {
    let tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
    tmp.set(new Uint8Array(buffer1), 0);
    tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
    return tmp.buffer;
}