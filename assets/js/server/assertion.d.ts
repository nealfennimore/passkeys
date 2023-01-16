export declare class Assertion {
    private static verify;
    static generateChallengeForCurrentUser(): Promise<string>;
    static verifyCredential(credential: PublicKeyCredential): Promise<boolean>;
}
