import { decode as _fromBase64Url, encode as _toBase64Url } from '@cfworker/base64url';
export declare const encode: (input?: string | undefined) => Uint8Array;
export declare const decode: (input?: BufferSource | undefined, options?: TextDecodeOptions | undefined) => string;
export declare function unescape(str: string): string;
export declare function escape(str: string): string;
export declare const marshal: {
    (value: any, replacer?: ((this: any, key: string, value: any) => any) | undefined, space?: string | number | undefined): string;
    (value: any, replacer?: (string | number)[] | null | undefined, space?: string | number | undefined): string;
};
export declare const unmarshal: (text: string, reviver?: ((this: any, key: string, value: any) => any) | undefined) => any;
export declare const toBase64Url: typeof _toBase64Url;
export declare const fromBase64Url: typeof _fromBase64Url;
export declare const safeEncode: (data: string) => Uint8Array;
export declare const safeDecode: (data: ArrayBuffer) => string;
export declare function concatBuffer(buffer1: ArrayBuffer, buffer2: ArrayBuffer): ArrayBufferLike;
export declare enum WebAuthnType {
    Create = "webauthn.create",
    Get = "webauthn.get"
}
