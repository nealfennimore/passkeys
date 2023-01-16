import { Assertion } from './assertion.js';
import { Attestation } from './attestation.js';
import { Context } from './context.js';
export class API {
}
API.getChallenge = Context.generateChallenge;
API.Attestation = Attestation;
API.Assertion = Assertion;
//# sourceMappingURL=index.js.map