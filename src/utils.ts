import base64url from "base64url";

export const encode = new TextEncoder().encode;
export const decode = new TextDecoder().decode;

export const toBase64 = base64url.encode;
export const fromBase64 = base64url.decode;

export const safeDecode = (data: ArrayBuffer) => toBase64(decode(data));
export const safeEncode = (data: string) => encode(fromBase64(data));