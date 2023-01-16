export const encode = new TextEncoder().encode;
export const decode = new TextDecoder().decode;
export function unescape(str) {
    return (str + '==='.slice((str.length + 3) % 4))
        .replace(/-/g, '+')
        .replace(/_/g, '/');
}
export function escape(str) {
    return str.replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}
export const toBase64Url = (str) => escape(btoa(str));
export const fromBase64Url = (str) => atob(unescape(str));
export const safeEncode = (data) => encode(fromBase64Url(data));
export const safeDecode = (data) => toBase64Url(decode(data));
export function concatBuffer(buffer1, buffer2) {
    let tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
    tmp.set(new Uint8Array(buffer1), 0);
    tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
    return tmp.buffer;
}
//# sourceMappingURL=utils.js.map