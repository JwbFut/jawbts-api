import { CodeInfo, Codes, type Code, type ErrorCode } from "./codes";

export interface ApiResponse<T> {
  success: boolean;
  code: Code;
  message: string;
  data: T;
}

function envelope<T>(code: Code, data: T): Response {
    const info = CodeInfo[code];
    return Response.json(
        {
            success: code === Codes.SUCCESS,
            code,
            message: info.message,
            data,
        },
        {
            status: info.status,
            // Token/PII-bearing API responses must never enter a shared cache.
            headers: { "Cache-Control": "no-store" },
        },
    );
}

export function ok<T>(data: T): Response {
    return envelope(Codes.SUCCESS, data);
}

export function fail(code: ErrorCode, data: unknown = null): Response {
    return envelope(code, data);
}

export class ApiError extends Error {
    constructor(
    public readonly code: ErrorCode,
    public readonly data: unknown = null,
    ) {
        super(CodeInfo[code].message);
    }
}
