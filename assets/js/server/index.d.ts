import { Assertion } from './assertion.js';
import { Attestation } from './attestation.js';
import { Context } from './context.js';
export declare class API {
    static getChallenge: typeof Context.generateChallenge;
    static Attestation: typeof Attestation;
    static Assertion: typeof Assertion;
}
