import { UserCredentialCache } from './context.js';
export declare class Attestation {
    static generateUser(): Promise<UserCredentialCache>;
    static storeCredential(credential: PublicKeyCredential): Promise<void>;
}
