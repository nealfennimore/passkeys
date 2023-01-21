import { Router } from 'itty-router';
import { Context } from './context';
import { Assertion } from './routes/assertion';
import { Attestation } from './routes/attestation';

const router = Router();

router.post('/attestation/generate', async (request) => {
	const ctx = new Context(request as unknown as Request);
	return Attestation.generateUser(ctx, request.cf.username as string);
});
router.post('/attestation/store', async (request) => {
	const ctx = new Context(request as unknown as Request);
	return Attestation.storeCredential(ctx, request.cf.credential as PublicKeyCredential);
});

router.post('/assertion/generate',  async (request) => {
	const ctx = new Context(request as unknown as Request);
	return Assertion.generateChallengeForCurrentUser(ctx);
});

router.post('/assertion/verify',  async (request) => {
	const ctx = new Context(request as unknown as Request);
	return Assertion.verifyCredential(ctx, request.cf.credential as PublicKeyCredential);
});


export interface Env {
}

export default {
	fetch: router.handle
};
