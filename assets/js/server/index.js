import { Router } from 'itty-router';
import { Assertion } from './assertion';
import { Attestation } from './attestation';
import { Context } from './context';
import * as response from './response';
const router = Router();
const withContext = (request, env) => {
    const ctx = new Context(request, env);
    request.ctx = ctx;
};
const requiresSession = (request, env) => {
    if (!request.ctx.hasSession) {
        return response.json({ error: 'Unauthorized' }, undefined, 401);
    }
};
router.post('*', withContext);
router.post('/attestation/generate', async (request) => {
    try {
        const data = await request.json();
        return await Attestation.generate(request.ctx, data.userId);
    }
    catch (err) {
        return response.json({ error: err?.message }, undefined, err.statusCode);
    }
});
router.post('/attestation/store', requiresSession, async (request) => {
    try {
        const data = (await request.json());
        return await Attestation.storeCredential(request.ctx, data);
    }
    catch (err) {
        return response.json({ error: err?.message }, undefined, err.statusCode);
    }
});
router.post('/assertion/generate', requiresSession, async (request) => {
    try {
        return await Assertion.generateChallengeForCurrentUser(request.ctx);
    }
    catch (err) {
        return response.json({ error: err?.message }, undefined, err.statusCode);
    }
});
router.post('/assertion/verify', requiresSession, async (request) => {
    try {
        const data = (await request.json());
        return await Assertion.verifyCredential(request.ctx, data);
    }
    catch (err) {
        return response.json({ error: err?.message }, undefined, err.statusCode);
    }
});
export default {
    fetch: router.handle,
};
//# sourceMappingURL=index.js.map