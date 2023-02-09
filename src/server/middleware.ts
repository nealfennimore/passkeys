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
    const ctx: Context = request.ctx;
    const body = (await request.json()) as any;
    ctx.body = body;
};

export const hasUserId = async (request: IRequest, env: Env) => {
    const ctx: Context = request.ctx;
    if (!ctx?.body?.userId) {
        return response.json({ error: 'No user ID' }, undefined, 400);
    }
};

const maxAge = 60 * 60 * 24;
export const maybeSetSession = async (request: IRequest, env: Env) => {
    const ctx: Context = request.ctx;
    const sessionId = ctx.cache.sessionId;
    if (!ctx.cache.hasSession) {
        ctx.headers = {
            'Set-Cookie': `session_id=${sessionId}; Max-Age=${maxAge}; Path=/; HttpOnly; SameSite=Lax; Secure;`,
        };
    }
};

export const requiresSession = (request: IRequest, env: Env) => {
    const ctx: Context = request.ctx;
    if (!ctx.cache.hasSession) {
        return response.json({ error: 'Unauthorized' }, undefined, 401);
    }
};
