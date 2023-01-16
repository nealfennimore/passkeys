import { Assertion } from './assertion.js';
import { Attestation } from './attestation.js';
import { Context } from './context.js';

export class API {   

    static getChallenge = Context.generateChallenge;
    static Attestation = Attestation;
    static Assertion = Assertion;
}