import { Request } from '@cloudflare/workers-types';
import { IRequest, Router } from 'itty-router';
import { Assertion } from './assertion';
import { Attestation } from './attestation';
import { Context } from './context';
import { Env } from './env';
import * as response from './response';

const router = Router();

const withContext = (request: IRequest, env: Env) => {
	const ctx = new Context(request as unknown as Request, env);
	request.ctx = ctx;
}

const requiresSession = (request: IRequest, env: Env) => {
	if(!request.ctx.hasSession) {
		return response.json({error: "Unauthorized"}, undefined, 401);
	}
}
const requiresNoSession = (request: IRequest, env: Env) => {
	if(request.ctx.hasSession) {
		return response.json({error: "Bad request"}, undefined, 400);
	}
}

router
	.post('*', withContext);

router.post('/attestation/generate', requiresNoSession, async (request) => {
	try {
		const data = await request.json();
		return await Attestation.generate(request.ctx, data.userId as string);
	} catch (err: any) {
		return response.json({ error: err?.message }, undefined, err.statusCode)
	}
});

router.post('/attestation/store', requiresSession, async (request) => {
	try {
		return await Attestation.storeCredential(request.ctx, request.cf.credential as PublicKeyCredential);
	} catch (err: any) {
		return response.json({ error: err?.message }, undefined, err.statusCode)
	}
});

router.post('/assertion/generate', requiresSession, async (request) => {
	try {
		return await Assertion.generateChallengeForCurrentUser(request.ctx);
	} catch (err: any) {
		return response.json({ error: err?.message }, undefined, err.statusCode)
	}
});

router.post('/assertion/verify', requiresSession, async (request) => {
	try {
		return await Assertion.verifyCredential(request.ctx, request.cf.credential as PublicKeyCredential);
	} catch (err: any) {
		return response.json({ error: err?.message }, undefined, err.statusCode)
	}
});


export default {
	fetch: router.handle
};
