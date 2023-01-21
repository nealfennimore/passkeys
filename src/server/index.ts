import { Router } from 'itty-router';
import { Context } from './context';
import { Assertion } from './routes/assertion';
import { Attestation } from './routes/attestation';

const router = Router();

router.post('/attestation/generate', async (request) => {
	const ctx = new Context(request as unknown as Request);
	const data = await request.json();
	return Attestation.generateUser(ctx, data.username);
});
router.post('/attestation/store', async (request) => {
	const ctx = new Context(request as unknown as Request);
	const data = await request.json();
	const credential = data.credential as PublicKeyCredential;
	return Attestation.storeCredential(ctx, credential);
});

router.post('/assertion/generate',  async (request) => {
	const ctx = new Context(request as unknown as Request);
	return Assertion.generateChallengeForCurrentUser(ctx);
});

router.post('/assertion/verify',  async (request) => {
	const ctx = new Context(request as unknown as Request);
	const data = await request.json();
	const credential = data.credential as PublicKeyCredential;
	return Assertion.verifyCredential(ctx, credential);
});


export interface Env {
}

export default {
	fetch: router.handle
};
