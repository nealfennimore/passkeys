import { Context } from './context';
import * as schema from './schema';
export declare class Assertion {
    private static verify;
    static generateChallengeForCurrentUser(ctx: Context): Promise<Response>;
    static verifyCredential(ctx: Context, payload: schema.Assertion.VerifyPayload): Promise<Response>;
}
