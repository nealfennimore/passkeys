export declare class StatusError extends Error {
    statusCode: number | undefined;
}
export declare class ForbiddenError extends StatusError {
    statusCode: number;
}
export declare class BadRequestError extends StatusError {
    statusCode: number;
}
