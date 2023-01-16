import { safeDecode } from "../utils.js";
export class Cache {
    static async retrieve(key) {
        const item = window.localStorage.getItem(key);
        return item ? JSON.parse(item) : {};
    }
    static async store(key, value) {
        window.localStorage.setItem(key, JSON.stringify(value));
    }
}
export class Context {
    static async getCurrentUser() {
        return await Cache.retrieve('currentUserId');
    }
    static async getCredentials() {
        const userId = await Context.getCurrentUser();
        return await Cache.retrieve(userId);
    }
    static async generateChallenge() {
        return safeDecode(crypto.getRandomValues(new Uint8Array(16)));
    }
}
//# sourceMappingURL=context.js.map