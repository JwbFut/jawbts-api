import { z } from "zod";
import { api, isDbError, parseBody, corsPreflight } from "@/lib/api";
import { Codes } from "@/lib/codes";
import { requireScope } from "@/lib/jwt-guard";
import { getPrisma } from "@/lib/prisma";
import { ApiError, ok } from "@/lib/response";
import {
    inTx,
    pruneExpiredSessions,
    resolveUserByName,
    revokeSessionTree,
    sha256Hex,
} from "@/lib/sessions";

export const OPTIONS = corsPreflight;

const RevokeRequestSchema = z.object({
    refreshToken: z.string().min(20).max(200).meta({ description: "The refresh token to revoke" }),
});

/**
 * Revokes one of the caller's refresh tokens — the only thing that can be
 * revoked. Requires a JWT whose scope list contains "api"; the JWT `sub` is
 * the GitHub username and the user is resolved by name. Removing the
 * REFRESH_TOKEN row's GITHUB_LOGIN parent ends the whole login pair (the
 * cap slot is freed), in a single transaction.
 */
export const POST = api(async (req) => {
    const claims = await requireScope(req, "api");
    const name = claims.sub;
    if (!name) {
        throw new ApiError(Codes.UNAUTHORIZED, { message: "Token has no subject" });
    }
    const { refreshToken } = await parseBody(req, RevokeRequestSchema);
    const db = await getPrisma();
    const user = await resolveUserByName(db, name);
    await inTx(db, async (tx) => {
        await pruneExpiredSessions(tx, user.id);
        const hash = await sha256Hex(refreshToken);
        // Accept the current token or the one it replaced, so a client that
        // lost the rotation response can still revoke.
        const found = await tx.session.findFirst({
            where: {
                userId: user.id,
                OR: [
                    { refreshTokenHash: hash },
                    { previousRefreshTokenHash: hash },
                ],
            },
        });
        if (!found) {
            throw new ApiError(Codes.NOT_FOUND, { message: "Refresh token not found" });
        }
        try {
            await revokeSessionTree(tx, found);
        } catch (error) {
            // A concurrent revoke already deleted it: treat as success.
            if (!isDbError(error, "P2025")) {
                throw error;
            }
        }
    });
    return ok({ revoked: true });
});
