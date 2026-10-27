import { z } from "zod";
import { api, parseBody, corsPreflight } from "@/lib/api";
import { Codes } from "@/lib/codes";
import { buildGithubAuthUrl } from "@/lib/github";
import { getPrisma } from "@/lib/prisma";
import { ApiError, ok } from "@/lib/response";
import {
    findUserByName,
    PENDING_LOGIN_TTL_MS,
    startLoginSession,
} from "@/lib/sessions";

export const OPTIONS = corsPreflight;

const LoginRequestSchema = z.object({
    username: z.string().min(1).max(39).meta({ description: "GitHub username (= the stored name)" }),
});

/**
 * Step 1 of the login: resolve the GitHub username to a stored user. There is
 * no registration — unknown usernames are rejected. Enforces the per-user
 * session cap and writes the pending GITHUB_LOGIN session (holding the OAuth
 * state), then returns the GitHub authorization URL the client should open.
 */
export const POST = api(async (req) => {
    const { username } = await parseBody(req, LoginRequestSchema);
    const db = await getPrisma();
    // Case-insensitive, but an ambiguous match throws 10010 instead of
    // silently picking one of the accounts.
    const user = await findUserByName(db, username);
    if (!user) {
        throw new ApiError(Codes.USER_NOT_FOUND, {
            message: "No account matches this GitHub username (registration is not supported)",
        });
    }
    const { state } = await startLoginSession(db, { userId: user.id });
    return ok({
        authUrl: buildGithubAuthUrl(state),
        stateExpiresIn: Math.floor(PENDING_LOGIN_TTL_MS / 1000),
    });
});
