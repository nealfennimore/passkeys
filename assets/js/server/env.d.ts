import { KVNamespace } from '@cloudflare/workers-types';
export interface Env {
    sessions: KVNamespace;
    pubkeys: KVNamespace;
    challenges: KVNamespace;
}
