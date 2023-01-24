export class StatusError extends Error {
}
export class ForbiddenError extends StatusError {
    constructor() {
        super(...arguments);
        this.statusCode = 403;
    }
}
export class BadRequestError extends StatusError {
    constructor() {
        super(...arguments);
        this.statusCode = 400;
    }
}
//# sourceMappingURL=error.js.map