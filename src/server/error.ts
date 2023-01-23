export class StatusError extends Error {
    statusCode: number | undefined;
}

export class ForbiddenError extends StatusError {
    statusCode = 403;
}

export class BadRequestError extends StatusError {
    statusCode = 400;
}
