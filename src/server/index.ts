import { Request } from '@cloudflare/workers-types';
import { Router } from 'itty-router';
import { Assertion } from './assertion';
import { Attestation } from './attestation';
import { Context } from './context';
import { Env } from './env';

const router = Router();

router.post('/attestation/generate', async (request, env: Env) => {
	const ctx = new Context(request as unknown as Request, env);
	const data = await request.json();
	return await Attestation.generateUser(ctx, data.username as string);
});
router.post('/attestation/store', async (request, env: Env) => {
	const ctx = new Context(request as unknown as Request, env);
	return await Attestation.storeCredential(ctx, request.cf.credential as PublicKeyCredential);
});

router.post('/assertion/generate',  async (request, env: Env) => {
	const ctx = new Context(request as unknown as Request, env);
	return await Assertion.generateChallengeForCurrentUser(ctx);
});

router.post('/assertion/verify',  async (request, env: Env) => {
	const ctx = new Context(request as unknown as Request, env);
	return await Assertion.verifyCredential(ctx, request.cf.credential as PublicKeyCredential);
});


export default {
	fetch: router.handle
};
