import { api, corsPreflight } from "@/lib/api";
import { Codes } from "@/lib/codes";
import { requireScope } from "@/lib/jwt-guard";
import { getPrisma } from "@/lib/prisma";
import { ApiError, ok } from "@/lib/response";
import { inTx, pruneExpiredSessions, resolveUserByName } from "@/lib/sessions";

export const OPTIONS = corsPreflight;

/**
 * Lists the caller's sessions. Requires a JWT (verified against the JWKS)
 * whose scope list contains "api". The JWT `sub` is the GitHub username; the
 * user is resolved by name first. Expired sessions are pruned in the same
 * transaction as the read.
 */
export const GET = api(async (req) => {
    const claims = await requireScope(req, "api");
    const name = claims.sub;
    if (!name) {
        throw new ApiError(Codes.UNAUTHORIZED, { message: "Token has no subject" });
    }
    const db = await getPrisma();
    const user = await resolveUserByName(db, name);
    const sessions = await inTx(db, async (tx) => {
        await pruneExpiredSessions(tx, user.id);
        return tx.session.findMany({
            where: { userId: user.id },
            orderBy: { createdAt: "desc" },
            select: {
                id: true,
                type: true,
                permissions: true,
                label: true,
                parentId: true,
                expiresAt: true,
                createdAt: true,
            },
        });
    });
    return ok({ sessions });
});
