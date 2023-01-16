export declare const encode: (input?: string | undefined) => Uint8Array;
export declare const decode: (input?: BufferSource | undefined, options?: TextDecodeOptions | undefined) => string;
export declare const toBase64Url: (input: any, encoding?: string | undefined) => string;
export declare const fromBase64Url: (base64url: string, encoding?: string | undefined) => string;
export declare const safeEncode: (data: string) => Uint8Array;
export declare const safeDecode: (data: ArrayBuffer) => string;
export declare function concatBuffer(buffer1: ArrayBuffer, buffer2: ArrayBuffer): ArrayBufferLike;
