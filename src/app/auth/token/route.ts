import { importJWK, SignJWT } from "jose";
import { z } from "zod";
import { api, parseBody, corsPreflight } from "@/lib/api";
import { Codes } from "@/lib/codes";
import { SessionType } from "@/generated/prisma/client";
import { getSigningKey, DELEGATED_TOKEN_TTL_SECONDS, JWT_ALG, JWT_ISSUER } from "@/lib/jwks";
import { requireScope } from "@/lib/jwt-guard";
import {
    isDelegablePermission,
    isUserPermission,
    Permissions,
} from "@/lib/permissions";
import { getPrisma } from "@/lib/prisma";
import { ApiError, ok } from "@/lib/response";
import {
    DELEGATED_REFRESH_TOKEN_TTL_MS,
    generateRefreshToken,
    inTx,
    MAX_DELEGATED_TOKENS,
    pruneExpiredSessions,
    resolveUserByName,
    sha256Hex,
} from "@/lib/sessions";

export const OPTIONS = corsPreflight;

const TokenRequestSchema = z.object({
    scope: z.array(z.string().min(1).max(64)).min(1).max(20),
    label: z.string().trim().min(1).max(64).optional(),
});

/**
 * Mints a delegated token carrying a subset of the caller's permissions.
 *
 * `issue_tokens` is the GitHub-only marker: only tokens issued by the
 * GitHub-login branch of `/auth/refresh` get it (it is not delegable, so a
 * minted token never has it, even after a delegated refresh). The other fail-closed
 * rules:
 * - the bearer token must carry `issue_tokens`;
 * - the user must still hold `issue_tokens` in the database;
 * - requested scopes must be known, delegable (never `issue_tokens`/`api`)
 *   and currently granted to the user;
 * - the minted token is bound to the caller's subject (`sub` is not a body
 *   parameter), lives for one day (delegated tokens), and gets its own
 *   rotatable refresh token (90 days) so it can be refreshed, listed and
 *   revoked like any session.
 */
export const POST = api(async (req) => {
    const claims = await requireScope(req, Permissions.ISSUE_TOKENS);
    const name = claims.sub;
    if (!name) {
        throw new ApiError(Codes.UNAUTHORIZED, { message: "Token has no subject" });
    }

    const { scope, label } = await parseBody(req, TokenRequestSchema);
    const requested = [...new Set(scope)];

    const db = await getPrisma();
    const user = await resolveUserByName(db, name);
    const granted = new Set(user.permissions.filter(isUserPermission));

    // The presented GitHub JWT must still belong to a live login session, so
    // revoking the session stops minting immediately instead of waiting for
    // the JWT to expire.
    const sid = claims.sid;
    if (typeof sid !== "string") {
        throw new ApiError(Codes.UNAUTHORIZED, {
            message: "Token has no session; refresh to get a new one",
        });
    }
    const session = await db.session.findUnique({ where: { id: sid } });
    if (
        !session ||
        session.type !== SessionType.REFRESH_TOKEN ||
        session.userId !== user.id ||
        session.expiresAt <= new Date()
    ) {
        throw new ApiError(Codes.UNAUTHORIZED, {
            message: "Session is no longer active; refresh to get a new one",
        });
    }

    if (!granted.has(Permissions.ISSUE_TOKENS)) {
        throw new ApiError(Codes.INSUFFICIENT_SCOPE, {
            message: "The issue_tokens permission is no longer granted to this user",
            required: Permissions.ISSUE_TOKENS,
        });
    }

    const unknown = requested.filter(
        (permission) => permission !== Permissions.API && !isUserPermission(permission),
    );
    if (unknown.length > 0) {
        throw new ApiError(Codes.BAD_REQUEST, {
            message: "Unknown permission(s)",
            issues: { scope: unknown },
        });
    }

    const nonDelegable = requested.filter((permission) => !isDelegablePermission(permission));
    if (nonDelegable.length > 0) {
        throw new ApiError(Codes.FORBIDDEN, {
            message: "Requested permission cannot be delegated",
            permissions: nonDelegable,
        });
    }

    const missing = requested.filter(
        (permission) => !isUserPermission(permission) || !granted.has(permission),
    );
    if (missing.length > 0) {
        throw new ApiError(Codes.INSUFFICIENT_SCOPE, {
            message: "Requested permission is not granted to this user",
            missing,
        });
    }

    const signingKey = await getSigningKey();
    const privateKey = await importJWK(JSON.parse(signingKey.privateKey), JWT_ALG);
    const nowSec = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({ scope: requested })
        .setProtectedHeader({ alg: JWT_ALG, kid: signingKey.kid })
        .setIssuer(JWT_ISSUER)
        .setSubject(user.name)
        .setJti(crypto.randomUUID())
        .setIssuedAt(nowSec)
        .setExpirationTime(nowSec + DELEGATED_TOKEN_TTL_SECONDS)
        .sign(privateKey);

    // The delegated token is a first-class session row: it carries its own
    // refresh token (rotated on every exchange) and shows up in the session
    // list so the owner can revoke it.
    const refreshToken = generateRefreshToken();
    const refreshTokenExpiresAt = new Date(Date.now() + DELEGATED_REFRESH_TOKEN_TTL_MS);
    // Row lock the user, then count/create in one transaction. This prevents
    // concurrent requests from both observing a free delegated-token slot.
    const delegated = await inTx(db, async (tx) => {
        await tx.user.update({
            where: { id: user.id },
            data: { updatedAt: new Date() },
        });
        await pruneExpiredSessions(tx, user.id);
        const activeDelegated = await tx.session.count({
            where: {
                userId: user.id,
                type: SessionType.DELEGATED_TOKEN,
                expiresAt: { gte: new Date() },
            },
        });
        if (activeDelegated >= MAX_DELEGATED_TOKENS) {
            throw new ApiError(Codes.SESSION_LIMIT, {
                message: `Already ${activeDelegated} active delegated tokens (max ${MAX_DELEGATED_TOKENS}); revoke one first`,
                active: activeDelegated,
                limit: MAX_DELEGATED_TOKENS,
            });
        }
        return tx.session.create({
            data: {
                userId: user.id,
                type: SessionType.DELEGATED_TOKEN,
                permissions: requested,
                label: label ?? null,
                refreshTokenHash: await sha256Hex(refreshToken),
                expiresAt: refreshTokenExpiresAt,
            },
        });
    });

    return ok({
        token,
        tokenType: "Bearer",
        alg: JWT_ALG,
        kid: signingKey.kid,
        scope: requested,
        label: delegated.label,
        expiresIn: DELEGATED_TOKEN_TTL_SECONDS,
        tokenId: delegated.id,
        refreshToken,
        refreshTokenExpiresAt: refreshTokenExpiresAt.toISOString(),
    });
});
