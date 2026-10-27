import { z } from "zod";
import { api, isDbError, parseBody, corsPreflight } from "@/lib/api";
import { Codes } from "@/lib/codes";
import {
    clearEmailChangeState,
    decodeEmailChangePlaceholder,
    hashEmailChangeToken,
} from "@/lib/email-change";
import { getPrisma } from "@/lib/prisma";
import { ApiError, ok } from "@/lib/response";

export const OPTIONS = corsPreflight;

const ConfirmRequestSchema = z.object({
    token: z.string().min(20).max(200),
});

/**
 * Confirms a pending email change: the one-time token mailed to the new
 * address becomes the account email. Unauthenticated by design — possession
 * of the token (delivered to that address) is the proof. Expiry or conflict
 * clears the token but deliberately leaves the placeholder in place; the old
 * address is never restored automatically.
 */
export const POST = api(async (req) => {
    const { token } = await parseBody(req, ConfirmRequestSchema);
    const db = await getPrisma();
    const tokenHash = await hashEmailChangeToken(token);
    const [user] = await db.user.findMany({
        where: { emailChangeTokenHash: tokenHash },
        take: 1,
    });
    if (!user) {
        throw new ApiError(Codes.TOKEN_INVALID, {
            message: "Invalid or already used confirmation token",
        });
    }
    const decoded = decodeEmailChangePlaceholder(user.email);
    if (!decoded) {
        await clearEmailChangeState(db, user).catch((error: unknown) => {
            console.error("Clearing invalid email change state failed", error);
        });
        throw new ApiError(Codes.TOKEN_INVALID, {
            message: "Invalid or already used confirmation token",
        });
    }
    if (!user.emailChangeExpiresAt || user.emailChangeExpiresAt <= new Date()) {
        await clearEmailChangeState(db, user).catch((error: unknown) => {
            console.error("Expired email change cleanup failed", error);
        });
        throw new ApiError(Codes.TOKEN_EXPIRED, {
            message: "Confirmation token expired; request the change again",
        });
    }

    // Another account may have claimed the address while this was pending.
    const clash = await db.user.findFirst({
        where: {
            NOT: { id: user.id },
            email: { equals: decoded.to, mode: "insensitive" },
        },
    });
    if (clash) {
        await clearEmailChangeState(db, user).catch((error: unknown) => {
            console.error("Email change conflict cleanup failed", error);
        });
        throw new ApiError(Codes.BAD_REQUEST, { message: "Email already exists" });
    }

    try {
        const { count } = await db.user.updateMany({
            where: { id: user.id, emailChangeTokenHash: tokenHash, email: user.email },
            data: {
                email: decoded.to.toLowerCase(),
                emailChangeTokenHash: null,
                emailChangeExpiresAt: null,
            },
        });
        if (count === 0) {
            // A concurrent request replaced or consumed this token.
            throw new ApiError(Codes.TOKEN_INVALID, {
                message: "Confirmation token is no longer active",
            });
        }
        return ok({ confirmed: true, email: decoded.to });
    } catch (error) {
        if (error instanceof ApiError) {
            throw error;
        }
        if (isDbError(error, "P2002", "23505")) {
            await clearEmailChangeState(db, user).catch((cleanupError: unknown) => {
                console.error("Email change conflict cleanup failed", cleanupError);
            });
            throw new ApiError(Codes.BAD_REQUEST, { message: "Email already exists" });
        }
        throw error;
    }
});
