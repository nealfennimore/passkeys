import { Request } from '@cloudflare/workers-types';
import { IRequest } from 'itty-router';
import { Context } from './context';
import { Env } from './env';
import * as response from './response';

export const withContext = (request: IRequest, env: Env) => {
    const ctx = new Context(request as unknown as Request, env);
    request.ctx = ctx;
};

export const setRequestBody = async (request: IRequest, env: Env) => {
    const body = (await request.json()) as any;
    request.ctx.body = body;
};

export const hasUserId = async (request: IRequest, env: Env) => {
    if (!request.ctx?.body?.userId) {
        return response.json({ error: 'No user ID' }, undefined, 400);
    }
};

export const maybeSetSession = async (request: IRequest, env: Env) => {
    const sessionId = request.ctx.sessionId;
    if (!request.ctx.hasSession) {
        request.ctx.headers = {
            'Set-Cookie': `session_id=${sessionId}; Max-Age=${
                60 * 60 * 24
            }; Path=/; HttpOnly; SameSite=None; Secure;`,
        };
    }
};

export const requiresSession = (request: IRequest, env: Env) => {
    if (!request.ctx.hasSession) {
        return response.json({ error: 'Unauthorized' }, undefined, 401);
    }
};
