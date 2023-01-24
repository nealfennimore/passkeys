import { Context } from './context';
import * as schema from './schema';
export declare class Attestation {
    static generate(ctx: Context, userId: string): Promise<Response>;
    static storeCredential(ctx: Context, payload: schema.Attestation.StoreCredentialPayload): Promise<Response>;
}
