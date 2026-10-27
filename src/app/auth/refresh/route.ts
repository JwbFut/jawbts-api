import { importJWK, SignJWT } from "jose";
import { z } from "zod";
import { api, parseBody, corsPreflight } from "@/lib/api";
import { recordActivity } from "@/lib/activity";
import { Codes } from "@/lib/codes";
import { SessionType } from "@/generated/prisma/client";
import {
    getSigningKey,
    DELEGATED_TOKEN_TTL_SECONDS,
    JWT_ALG,
    JWT_ISSUER,
    GITHUB_TOKEN_TTL_SECONDS,
} from "@/lib/jwks";
import {
    githubTokenScope,
    isDelegablePermission,
    isUserPermission,
} from "@/lib/permissions";
import { getPrisma } from "@/lib/prisma";
import { ApiError, ok } from "@/lib/response";
import {
    generateRefreshToken,
    getClientIp,
    getUserAgent,
    inTx,
    pruneExpiredSessions,
    revokeSessionTree,
    sha256Hex,
} from "@/lib/sessions";

export const OPTIONS = corsPreflight;

const RefreshRequestSchema = z.object({
    refreshToken: z.string().min(20).max(200),
});

/**
 * Exchanges a refresh token for a JWT and rotates the refresh token (single
 * use); presenting the previous one again is treated as theft and revokes the
 * family. Two session kinds are supported:
 * - a GitHub login refresh (`REFRESH_TOKEN`) gets `api` plus the user's current
 *   permissions and a 1-day JWT, and may alert on a new device;
 * - a delegated token (`DELEGATED_TOKEN`) gets its stored permissions
 *   re-intersected with the user's current grants and a 1-day JWT; it alerts
 *   on a new device fingerprint like any other refresh.
 * Validation and rotation run in one transaction when the transport supports
 * it. The caller's IP/user-agent fingerprint is recorded (and emailed when
 * new) before any JWT is signed; raw IP/UA are never persisted.
 */
export const POST = api(async (req) => {
    const { refreshToken } = await parseBody(req, RefreshRequestSchema);
    const db = await getPrisma();
    const ip = getClientIp(req);
    const userAgent = getUserAgent(req);
    const presentedHash = await sha256Hex(refreshToken);

    // Read-only validation (plus revocation of expired/replayed pairs). The
    // token is not consumed yet: an alert failure below must leave it usable
    // so the client can retry.
    const { session, user } = await inTx(db, async (tx) => {
        const found = await tx.session.findFirst({
            where: {
                OR: [
                    { refreshTokenHash: presentedHash },
                    { previousRefreshTokenHash: presentedHash },
                ],
            },
        });
        if (!found) {
            throw new ApiError(Codes.UNAUTHORIZED, { message: "Unknown refresh token" });
        }
        if (found.expiresAt <= new Date()) {
            await revokeSessionTree(tx, found);
            throw new ApiError(Codes.TOKEN_EXPIRED, {
                message: "Refresh token expired; log in again",
            });
        }
        if (found.previousRefreshTokenHash === presentedHash) {
            // A token that was already rotated is being replayed: assume theft
            // and end the whole login pair.
            await revokeSessionTree(tx, found);
            throw new ApiError(Codes.TOKEN_INVALID, {
                message: "Refresh token reuse detected; session revoked",
            });
        }
        await pruneExpiredSessions(tx, found.userId);
        const owner = await tx.user.findUnique({ where: { id: found.userId } });
        if (!owner) {
            throw new ApiError(Codes.USER_NOT_FOUND, { message: "Session user no longer exists" });
        }
        return { session: found, user: owner };
    });

    const isDelegated = session.type === SessionType.DELEGATED_TOKEN;
    let scope: string[];
    let ttlSeconds: number;
    if (isDelegated) {
        // Re-intersect with the user's current permissions so a revoked grant
        // disappears from the next delegated token. Delegable only: a row can
        // never reintroduce issue_tokens into a minted token.
        const current = new Set(user.permissions.filter(isUserPermission));
        scope = session.permissions.filter(
            (permission) =>
                isUserPermission(permission) &&
                isDelegablePermission(permission) &&
                current.has(permission),
        );
        if (scope.length === 0) {
            await revokeSessionTree(db, session).catch((error: unknown) => {
                console.error("Delegated token revocation failed", error);
            });
            throw new ApiError(Codes.TOKEN_INVALID, {
                message: "Delegated token has no permissions left; token revoked",
            });
        }
        ttlSeconds = DELEGATED_TOKEN_TTL_SECONDS;
    } else {
        scope = githubTokenScope(user.permissions);
        ttlSeconds = GITHUB_TOKEN_TTL_SECONDS;
    }

    // Every login and every refresh (login or delegated) alerts on a new
    // device fingerprint. A placeholder email means the account is mid change:
    // it is not deliverable, so recordActivity skips the alert entirely.
    await recordActivity(db, {
        userId: user.id,
        email: user.email,
        ip,
        userAgent,
        kind: "refresh",
    });

    const signingKey = await getSigningKey();
    const privateKey = await importJWK(JSON.parse(signingKey.privateKey), JWT_ALG);
    const nowSec = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({ scope, sid: session.id })
        .setProtectedHeader({ alg: JWT_ALG, kid: signingKey.kid })
        .setIssuer(JWT_ISSUER)
        .setSubject(user.name)
        .setJti(crypto.randomUUID())
        .setIssuedAt(nowSec)
        .setExpirationTime(nowSec + ttlSeconds)
        .sign(privateKey);

    const nextRefreshToken = generateRefreshToken();
    // Single-statement rotation, conditional on the presented hash so two
    // concurrent exchanges cannot both succeed. For delegated tokens the
    // (possibly shrunken) scope is persisted too.
    const rotated = await db.session.updateMany({
        where: { id: session.id, refreshTokenHash: presentedHash },
        data: {
            refreshTokenHash: await sha256Hex(nextRefreshToken),
            previousRefreshTokenHash: presentedHash,
            ...(isDelegated ? { permissions: scope } : {}),
        },
    });
    if (rotated.count === 0) {
        // Lost a race: another exchange consumed this token. Treat it as
        // reuse and end the family.
        await revokeSessionTree(db, session).catch((error: unknown) => {
            console.error("Refresh reuse revocation failed", error);
        });
        throw new ApiError(Codes.TOKEN_INVALID, {
            message: "Refresh token already used; session revoked",
        });
    }

    return ok({
        token,
        tokenType: "Bearer",
        alg: JWT_ALG,
        kid: signingKey.kid,
        scope,
        expiresIn: ttlSeconds,
        refreshToken: nextRefreshToken,
        refreshTokenExpiresAt: session.expiresAt.toISOString(),
    });
});
