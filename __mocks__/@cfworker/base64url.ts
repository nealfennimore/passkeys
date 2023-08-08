export const decode = (data: string) =>
    Buffer.from(data, 'base64url').toString();
export const encode = (data: ArrayBuffer) =>
    Buffer.from(data).toString('base64url');
