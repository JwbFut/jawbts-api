import { createLocalJWKSet, jwtVerify, type JWTPayload } from "jose";
import {
    JOSEAlgNotAllowed,
    JWSInvalid,
    JWTClaimValidationFailed,
    JWTExpired,
    JWTInvalid,
    JWKSNoMatchingKey,
    JWSSignatureVerificationFailed,
} from "jose/errors";
import type { NextRequest } from "next/server";
import { Codes, type ErrorCode } from "./codes";
import { getPublicJwks, JWT_ALG, JWT_ISSUER } from "./jwks";
import { ApiError } from "./response";

export interface AuthFailure {
    code: ErrorCode;
    where: string;
    reason: string;
}

const TOKEN_VERIFICATION_ERRORS = [
    JWTExpired,
    JWTClaimValidationFailed,
    JWSSignatureVerificationFailed,
    JWKSNoMatchingKey,
    JOSEAlgNotAllowed,
    JWSInvalid,
    JWTInvalid,
] as const;

/**
 * True when the error describes a problem with the token. Anything else from
 * the key resolver (JWKS transport, malformed key set, timeout, generic
 * JOSEError) is an infrastructure failure, not an invalid token.
 */
export function isTokenVerificationError(error: unknown): boolean {
    return TOKEN_VERIFICATION_ERRORS.some((ErrorType) => error instanceof ErrorType);
}

/** Maps a jose verification error to the specific code saying where it failed. */
export function joseFailure(error: unknown): AuthFailure {
    if (error instanceof JWTExpired) {
        return {
            code: Codes.TOKEN_EXPIRED,
            where: `claim "${error.claim}"`,
            reason: error.message,
        };
    }
    if (error instanceof JWTClaimValidationFailed) {
        return {
            code: Codes.TOKEN_INVALID,
            where: `claim "${error.claim}" (${error.reason})`,
            reason: error.message,
        };
    }
    if (error instanceof JWSSignatureVerificationFailed) {
        return {
            code: Codes.TOKEN_INVALID,
            where: "signature",
            reason: "signature verification failed",
        };
    }
    if (error instanceof JWKSNoMatchingKey) {
        return {
            code: Codes.TOKEN_INVALID,
            where: "kid",
            reason: "no key in the JWKS matches the token kid",
        };
    }
    if (error instanceof JOSEAlgNotAllowed) {
        return { code: Codes.TOKEN_INVALID, where: "alg", reason: error.message };
    }
    if (error instanceof JWSInvalid || error instanceof JWTInvalid) {
        return { code: Codes.TOKEN_INVALID, where: "token format", reason: error.message };
    }
    return {
        code: Codes.TOKEN_INVALID,
        where: "verification",
        reason: error instanceof Error ? error.message : "token verification failed",
    };
}

export function toAuthApiError(error: unknown): ApiError {
    const failure = joseFailure(error);
    return new ApiError(failure.code, {
        valid: false,
        where: failure.where,
        reason: failure.reason,
    });
}

/**
 * Verifies the Authorization: Bearer JWT against the published JWKS and
 * requires `required` in its scope list (scope is a list of strings).
 * - missing header -> 10002 UNAUTHORIZED
 * - jose failure   -> 10005 TOKEN_EXPIRED / 10006 TOKEN_INVALID (with where/reason)
 * - scope missing  -> 10007 INSUFFICIENT_SCOPE
 */
export async function requireScope(req: NextRequest, required: string): Promise<JWTPayload> {
    const header = req.headers.get("authorization") ?? "";
    const [scheme, token, ...extra] = header.trim().split(/\s+/);
    if (
        extra.length > 0 ||
        !scheme ||
        scheme.toLowerCase() !== "bearer" ||
        !token
    ) {
        throw new ApiError(Codes.UNAUTHORIZED, {
            message: "Authorization: Bearer <token> is required",
        });
    }
    const jwks = await getPublicJwks();
    let payload: JWTPayload;
    try {
        ({ payload } = await jwtVerify(token, createLocalJWKSet(jwks), {
            issuer: JWT_ISSUER,
            // Pin the algorithm: never let the token header choose it.
            algorithms: [JWT_ALG],
        }));
    } catch (error) {
        throw toAuthApiError(error);
    }
    const scope = payload.scope;
    if (!Array.isArray(scope) || !scope.includes(required)) {
        throw new ApiError(Codes.INSUFFICIENT_SCOPE, {
            message: `token scope must include "${required}"`,
            required,
            scope: Array.isArray(scope) ? scope : null,
        });
    }
    return payload;
}
