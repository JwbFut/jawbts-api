import { NextRequest } from "next/server";
import { ZodType, z } from "zod";
import { Codes } from "./codes";
import { ApiError, fail } from "./response";

type Handler<C> = (req: NextRequest, ctx: C) => Promise<Response> | Response;

export { corsPreflight } from "./cors";

/**
 * Wraps a route handler so every endpoint always returns the unified
 * { success, code, data } envelope with the mapped HTTP status, even on errors.
 */
export function api<C>(handler: Handler<C>): Handler<C> {
    return async (req, ctx) => {
        try {
            return await handler(req, ctx);
        } catch (error) {
            if (error instanceof ApiError) {
                return fail(error.code, error.data);
            }
            if (error instanceof z.ZodError) {
                return fail(Codes.BAD_REQUEST, {
                    issues: z.flattenError(error).fieldErrors,
                });
            }
            console.error(error);
            return fail(Codes.INTERNAL_ERROR);
        }
    };
}

/** Bodies are small JSON envelopes; cap them instead of buffering anything. */
export const MAX_BODY_BYTES = 64 * 1024;

async function readBody(req: NextRequest): Promise<string> {
    const reader = req.body?.getReader();
    if (!reader) {
        return "";
    }
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
        for (;;) {
            const { done, value } = await reader.read();
            if (done) {
                break;
            }
            if (!value) {
                continue;
            }
            total += value.byteLength;
            if (total > MAX_BODY_BYTES) {
                await reader.cancel().catch(() => {});
                throw new ApiError(Codes.BAD_REQUEST, {
                    issues: { body: [`request body must be at most ${MAX_BODY_BYTES} bytes`] },
                });
            }
            chunks.push(value);
        }
    } catch (error) {
        if (error instanceof ApiError) {
            throw error;
        }
        throw new ApiError(Codes.BAD_REQUEST, {
            issues: { body: ["could not read request body"] },
        });
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
    }
    return new TextDecoder().decode(bytes);
}

function parseJson(raw: string): unknown {
    try {
        return JSON.parse(raw);
    } catch {
        throw new ApiError(Codes.BAD_REQUEST, {
            issues: { body: ["invalid JSON"] },
        });
    }
}

export async function parseBody<T>(req: NextRequest, schema: ZodType<T>): Promise<T> {
    const raw = await readBody(req);
    if (!raw) {
        throw new ApiError(Codes.BAD_REQUEST, {
            issues: { body: ["request body is required"] },
        });
    }
    return schema.parse(parseJson(raw));
}

export async function parseParams<C extends { params: Promise<unknown> }, T>(
    ctx: C,
    schema: ZodType<T>,
): Promise<T> {
    return schema.parse(await ctx.params);
}

/**
 * Matches a database error by Prisma code (e.g. "P2002") or SQLSTATE (e.g.
 * "23505"). With driver adapters some errors surface as raw driver errors
 * carrying the SQLSTATE instead of a wrapped Prisma error.
 */
export function isDbError(error: unknown, prismaCode: string, sqlState?: string): boolean {
    if (!(error instanceof Error) || !("code" in error)) {
        return false;
    }
    const code = (error as { code?: unknown }).code;
    return code === prismaCode || (sqlState !== undefined && code === sqlState);
}
