import { D1Database, KVNamespace } from '@cloudflare/workers-types';

export interface Env {
    sessions: KVNamespace;
    challenges: KVNamespace;
    DB: D1Database;
}
