interface UserCredential {
    kid: string;
    jwk: JsonWebKey;
}
interface UserCredentialCache {
    userId: string;
    challenge: string;
    credentials?: [UserCredential];
}
declare class Context {
    static getCurrentUser(): Promise<string>;
    static getCredentials(): Promise<UserCredentialCache>;
    static generateChallenge(): Promise<string>;
}
declare class Attestation {
    static generateUser(): Promise<UserCredentialCache>;
    static storeCredential(credential: PublicKeyCredential): Promise<void>;
}
declare class Assertion {
    private static verify;
    static generateChallengeForCurrentUser(): Promise<string>;
    static verifyCredential(credential: PublicKeyCredential): Promise<boolean>;
}
export declare class API {
    static getChallenge: typeof Context.generateChallenge;
    static Attestation: typeof Attestation;
    static Assertion: typeof Assertion;
}
export {};
