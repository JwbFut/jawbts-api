import { z } from "zod";
import { api, parseBody, corsPreflight } from "@/lib/api";
import { Codes } from "@/lib/codes";
import { requireScope } from "@/lib/jwt-guard";
import { getPrisma } from "@/lib/prisma";
import { ApiError, ok } from "@/lib/response";
import {
    inTx,
    pruneExpiredSessions,
    resolveUserByName,
    revokeSessionTree,
} from "@/lib/sessions";

export const OPTIONS = corsPreflight;

const RevokeRequestSchema = z.object({
    sessionId: z.string().min(1).max(64).meta({ description: "The session id to revoke" }),
});

/**
 * Revokes one of the caller's sessions by id. Requires a JWT whose scope list
 * contains "api"; the JWT `sub` is the GitHub username and the user is
 * resolved by name. Revoking a REFRESH_TOKEN child removes its GITHUB_LOGIN
 * parent (the whole login pair); revoking a DELEGATED_TOKEN removes only that
 * token. A session belonging to another user is a 404.
 */
export const POST = api(async (req) => {
    const claims = await requireScope(req, "api");
    const name = claims.sub;
    if (!name) {
        throw new ApiError(Codes.UNAUTHORIZED, { message: "Token has no subject" });
    }
    const { sessionId } = await parseBody(req, RevokeRequestSchema);
    const db = await getPrisma();
    const user = await resolveUserByName(db, name);
    await inTx(db, async (tx) => {
        await pruneExpiredSessions(tx, user.id);
        // Scope the lookup to the caller: a session id alone is never enough
        // to revoke another account's session.
        const found = await tx.session.findFirst({
            where: { id: sessionId, userId: user.id },
        });
        if (!found) {
            throw new ApiError(Codes.NOT_FOUND, { message: "Session not found" });
        }
        await revokeSessionTree(tx, found);
    });
    return ok({ revoked: true });
});
