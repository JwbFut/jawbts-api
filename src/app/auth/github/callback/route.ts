import { z } from "zod";
import { api, parseBody, corsPreflight } from "@/lib/api";
import { recordActivity } from "@/lib/activity";
import { Codes } from "@/lib/codes";
import { exchangeCodeForToken, fetchGithubUser } from "@/lib/github";
import { getPrisma } from "@/lib/prisma";
import { ApiError, ok } from "@/lib/response";
import {
    completeLoginSession,
    findPendingLoginByState,
    getClientIp,
    getUserAgent,
    REFRESH_TOKEN_TTL_SECONDS,
} from "@/lib/sessions";

export const OPTIONS = corsPreflight;

const CallbackRequestSchema = z.object({
    code: z.string().min(1).meta({ description: "Authorization code from the GitHub redirect" }),
    state: z.string().min(1).meta({ description: "The state returned by /auth/github/login" }),
});

/**
 * Step 2 of the login: the client forwards the GitHub redirect parameters.
 * The state is matched against the pending GITHUB_LOGIN session, the code is
 * exchanged for a GitHub token and the GitHub ID is checked against the
 * stored user; then one transaction attaches the REFRESH_TOKEN row and
 * realizes the session (consuming the one-time state).
 */
export const POST = api(async (req) => {
    const { code, state } = await parseBody(req, CallbackRequestSchema);
    const db = await getPrisma();
    const pending = await findPendingLoginByState(db, state);
    const user = await db.user.findUnique({ where: { id: pending.userId } });
    if (!user) {
        throw new ApiError(Codes.USER_NOT_FOUND, { message: "User no longer exists" });
    }
    const accessToken = await exchangeCodeForToken(code);
    const githubUser = await fetchGithubUser(accessToken);
    if (String(githubUser.id) !== user.githubId) {
        throw new ApiError(Codes.IDENTITY_MISMATCH, {
            where: "GitHub identity check",
            message: "The GitHub account does not match this user",
        });
    }
    const ip = getClientIp(req);
    const userAgent = getUserAgent(req);
    // Alert on a fingerprint unseen in the last 7 days. This runs before the
    // session is realized, so a failed alert fails the login (no session).
    await recordActivity(db, {
        userId: user.id,
        email: user.email,
        ip,
        userAgent,
        kind: "login",
    });
    const created = await completeLoginSession(db, { state });
    return ok({
        refreshToken: created.refreshToken,
        sessionId: created.sessionId,
        tokenType: "Bearer",
        expiresAt: created.expiresAt.toISOString(),
        expiresIn: REFRESH_TOKEN_TTL_SECONDS,
    });
});
