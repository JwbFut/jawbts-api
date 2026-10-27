import { jwtVerify } from "jose";
import { z } from "zod";
import { api, parseBody, corsPreflight } from "@/lib/api";
import { Codes } from "@/lib/codes";
import { JWT_ALG, JWT_ISSUER } from "@/lib/jwks";
import { getRemoteJwks } from "@/lib/jwks-remote";
import { isTokenVerificationError, toAuthApiError } from "@/lib/jwt-guard";
import { ApiError, ok } from "@/lib/response";

export const OPTIONS = corsPreflight;

/** Verification is unauthenticated, so the token is capped tightly. */
const MAX_TOKEN_CHARS = 4096;

const VerifyRequestSchema = z.object({
    token: z.string().min(1).max(MAX_TOKEN_CHARS),
});

/**
 * Verifies a JWT against the published JWKS, fetched over HTTP by jose's
 * remote key set (cached for JWKS_CACHE_MAX_AGE_MS, refetched when cooldown
 * allows and the token names an unknown `kid` — i.e. key rotation). No
 * database access. A JWKS transport/format failure is a server error (10500);
 * token problems stay fine-grained 10005/10006.
 */
export const POST = api(async (req) => {
    const { token } = await parseBody(req, VerifyRequestSchema);
    try {
        const { payload, protectedHeader } = await jwtVerify(token, getRemoteJwks(req), {
            issuer: JWT_ISSUER,
            algorithms: [JWT_ALG],
        });
        return ok({ valid: true, header: protectedHeader, payload });
    } catch (error) {
        if (!isTokenVerificationError(error)) {
            console.error("Verify: JWKS unavailable", error);
            throw new ApiError(Codes.INTERNAL_ERROR, { message: "JWKS is unavailable" });
        }
        throw toAuthApiError(error);
    }
});
