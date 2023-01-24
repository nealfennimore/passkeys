import { Request } from '@cloudflare/workers-types';
import { IRequest } from 'itty-router';
import { Context } from './context';
import { Env } from './env';
import * as response from './response';
import * as schema from './schema';

export const withContext = (request: IRequest, env: Env) => {
    const ctx = new Context(request as unknown as Request, env);
    request.ctx = ctx;
};

export const setUserId = async (request: IRequest, env: Env) => {
    const data = (await request.json()) as
        | schema.Attestation.ChallengePayload
        | schema.Assertion.ChallengePayload;

    if (!data.userId) {
        return response.json({ error: 'No user ID' }, undefined, 400);
    }

    request.ctx.userId = data.userId;
};

export const maybeSetSession = async (request: IRequest, env: Env) => {
    const sessionId = request.ctx.sessionId;
    if (!request.ctx.hasSession) {
        await request.ctx.setCurrentUserId(sessionId, request.ctx.userId);
        request.ctx.headers = {
            'Set-Cookie': `session_id=${sessionId}; Path=/; HttpOnly; SameSite=None; Secure;`,
        };
    }
};

export const requiresSession = (request: IRequest, env: Env) => {
    if (!request.ctx.hasSession) {
        return response.json({ error: 'Unauthorized' }, undefined, 401);
    }
};
