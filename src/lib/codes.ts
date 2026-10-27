/**
 * Single source of truth for all business codes and their HTTP status mapping.
 * Add new codes here only — never hardcode codes in route files.
 */
export const Codes = {
    SUCCESS: 200,
    NOT_FOUND: 10000,
    BAD_REQUEST: 10001,
    UNAUTHORIZED: 10002,
    FORBIDDEN: 10003,
    SESSION_LIMIT: 10004,
    TOKEN_EXPIRED: 10005,
    TOKEN_INVALID: 10006,
    INSUFFICIENT_SCOPE: 10007,
    USER_NOT_FOUND: 10008,
    OAUTH_FAILED: 10009,
    IDENTITY_MISMATCH: 10010,
    OAUTH_STATE_INVALID: 10011,
    ACTIVITY_ALERT_FAILED: 10012,
    NOTIFICATION_FAILED: 10013,
    RATE_LIMITED: 10014,
    EMAIL_CHANGE_STATE_INVALID: 10015,
    NO_SIGNING_KEY: 10016,
    INTERNAL_ERROR: 10500,
} as const;

export type Code = (typeof Codes)[keyof typeof Codes];
export type ErrorCode = Exclude<Code, typeof Codes.SUCCESS>;

interface CodeInfo {
  message: string;
  status: number;
}

export const CodeInfo: Record<Code, CodeInfo> = {
    [Codes.SUCCESS]: { message: "OK", status: 200 },
    [Codes.NOT_FOUND]: { message: "Not Found", status: 404 },
    [Codes.BAD_REQUEST]: { message: "Bad Request", status: 400 },
    [Codes.UNAUTHORIZED]: { message: "Unauthorized", status: 401 },
    [Codes.FORBIDDEN]: { message: "Forbidden", status: 403 },
    [Codes.SESSION_LIMIT]: { message: "Session Limit Reached", status: 429 },
    [Codes.TOKEN_EXPIRED]: { message: "Token Expired", status: 401 },
    [Codes.TOKEN_INVALID]: { message: "Token Invalid", status: 401 },
    [Codes.INSUFFICIENT_SCOPE]: { message: "Insufficient Scope", status: 403 },
    [Codes.USER_NOT_FOUND]: { message: "User Not Found", status: 404 },
    [Codes.OAUTH_FAILED]: { message: "OAuth Failed", status: 401 },
    [Codes.IDENTITY_MISMATCH]: { message: "Identity Mismatch", status: 403 },
    [Codes.OAUTH_STATE_INVALID]: { message: "OAuth State Invalid", status: 400 },
    [Codes.ACTIVITY_ALERT_FAILED]: { message: "Activity Alert Failed", status: 502 },
    [Codes.NOTIFICATION_FAILED]: { message: "Notification Failed", status: 502 },
    [Codes.RATE_LIMITED]: { message: "Too Many Requests", status: 429 },
    [Codes.EMAIL_CHANGE_STATE_INVALID]: { message: "Email Change State Invalid", status: 409 },
    [Codes.NO_SIGNING_KEY]: { message: "No Signing Key Available", status: 500 },
    [Codes.INTERNAL_ERROR]: { message: "Internal Server Error", status: 500 },
};
