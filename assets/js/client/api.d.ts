import * as schema from '../server/schema.js';
export declare namespace Attestation {
    function generate(userId: string): Promise<{
        challenge: string;
    }>;
    function store(credential: PublicKeyCredential): Promise<schema.Attestation.StoreCredentialResponse>;
}
export declare namespace Assertion {
    function generate(): Promise<{
        challenge: string;
    }>;
    function verify(credential: PublicKeyCredential): Promise<schema.Assertion.VerifyResponse>;
}
