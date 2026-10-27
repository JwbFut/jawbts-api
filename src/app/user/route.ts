import { api, isDbError, parseBody, corsPreflight } from "@/lib/api";
import { Codes } from "@/lib/codes";
import {
    decodeEmailChangePlaceholder,
    EMAIL_CHANGE_COOLDOWN_MS,
    EMAIL_CHANGE_TTL_MS,
    encodeEmailChangePlaceholder,
    generateEmailChangeToken,
    hashEmailChangeToken,
    isPlaceholderEmail,
    restoreEmailAfterFailedChange,
} from "@/lib/email-change";
import { requireScope } from "@/lib/jwt-guard";
import {
    sendEmailChangeCancelledNotice,
    sendEmailChangeConfirmation,
    sendEmailChangeRequestedNotice,
} from "@/lib/notifications";
import { getPrisma } from "@/lib/prisma";
import { ApiError, ok } from "@/lib/response";
import { resolveUserByName } from "@/lib/sessions";
import { UpdateUserSchema } from "./schemas";

export const OPTIONS = corsPreflight;

type UserRecord = Awaited<ReturnType<typeof resolveUserByName>>;

/**
 * Hide the email only while it is the encoded placeholder. A real address is
 * always returned; pending details live exclusively in the placeholder.
 */
function presentUser(user: UserRecord) {
    return {
        id: user.id,
        name: user.name,
        githubId: user.githubId,
        permissions: user.permissions,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
        ...(isPlaceholderEmail(user.email) ? {} : { email: user.email }),
    };
}

/** Self-service only: the caller's identity comes from the JWT (`sub`, the
 * GitHub username), there is no way to read or change another user through
 * this API. */
export const GET = api(async (req) => {
    const claims = await requireScope(req, "api");
    const name = claims.sub;
    if (!name) {
        throw new ApiError(Codes.UNAUTHORIZED, { message: "Token has no subject" });
    }
    const db = await getPrisma();
    const user = await resolveUserByName(db, name);
    return ok(presentUser(user));
});

/** Only the email may be changed; accounts are managed outside this API. */
export const PATCH = api(async (req) => {
    const claims = await requireScope(req, "api");
    const name = claims.sub;
    if (!name) {
        throw new ApiError(Codes.UNAUTHORIZED, { message: "Token has no subject" });
    }
    const body = await parseBody(req, UpdateUserSchema);
    const db = await getPrisma();
    const existing = await resolveUserByName(db, name);

    const placeholder = isPlaceholderEmail(existing.email);
    const decoded = placeholder
        ? decodeEmailChangePlaceholder(existing.email)
        : null;
    if (placeholder && !decoded) {
        // Fail closed rather than guess at a corrupt pending state.
        throw new ApiError(Codes.EMAIL_CHANGE_STATE_INVALID, {
            message: "Pending email change is invalid; an operator can reset it",
        });
    }
    const activeEmail = decoded?.from ?? existing.email;
    const newEmail = body.email;
    if (!placeholder && activeEmail.toLowerCase() === newEmail.toLowerCase()) {
        return ok(presentUser(existing));
    }

    const sinceLast = existing.emailChangeLastSentAt
        ? Date.now() - existing.emailChangeLastSentAt.getTime()
        : Number.POSITIVE_INFINITY;
    if (sinceLast < EMAIL_CHANGE_COOLDOWN_MS) {
        throw new ApiError(Codes.RATE_LIMITED, {
            message: "Email change requested too recently; try again later",
            retryAfterSeconds: Math.ceil(
                (EMAIL_CHANGE_COOLDOWN_MS - sinceLast) / 1000,
            ),
        });
    }

    // Only active addresses can be checked in SQL; the requested address is
    // encoded in placeholders (confirmed authoritatively by /auth/email/confirm).
    const clash = await db.user.findFirst({
        where: {
            email: { equals: newEmail, mode: "insensitive" },
            NOT: { id: existing.id },
        },
    });
    if (clash) {
        throw new ApiError(Codes.BAD_REQUEST, { message: "Email already exists" });
    }

    const token = generateEmailChangeToken();
    const tokenHash = await hashEmailChangeToken(token);
    const expiresAt = new Date(Date.now() + EMAIL_CHANGE_TTL_MS);
    const at = new Date();
    const stageData = {
        email: encodeEmailChangePlaceholder({
            from: activeEmail,
            to: newEmail,
            expiresAt,
        }),
        emailChangeTokenHash: tokenHash,
        emailChangeExpiresAt: expiresAt,
        emailChangeLastSentAt: at,
    };
    let staged: UserRecord;
    try {
        // Optimistic concurrency: only stage if the row still matches what we
        // read. A concurrent confirm/PATCH must win or lose atomically.
        const { count } = await db.user.updateMany({
            where: {
                id: existing.id,
                email: existing.email,
                emailChangeTokenHash: existing.emailChangeTokenHash,
            },
            data: stageData,
        });
        if (count === 0) {
            throw new ApiError(Codes.EMAIL_CHANGE_STATE_INVALID, {
                message: "Email change state changed; retry the request",
            });
        }
        staged = { ...existing, ...stageData };
    } catch (error) {
        if (error instanceof ApiError) {
            throw error;
        }
        if (isDbError(error, "P2002", "23505")) {
            throw new ApiError(Codes.BAD_REQUEST, { message: "Email already exists" });
        }
        throw error;
    }

    let oldNotified = false;
    try {
        // Both notices are required. The old address is warned first; the new
        // address gets the one-time token. On failure the request fails 10013
        // and the previous address is restored (the change never happened).
        await sendEmailChangeRequestedNotice({ oldEmail: activeEmail, newEmail, at });
        oldNotified = true;
        await sendEmailChangeConfirmation({
            oldEmail: activeEmail,
            newEmail,
            token,
            expiresAt,
            at,
        });
    } catch (error) {
        if (oldNotified) {
            await sendEmailChangeCancelledNotice({
                oldEmail: activeEmail,
                newEmail,
                at,
            }).catch((noticeError: unknown) => {
                console.error("Email change cancellation notice failed", noticeError);
            });
        }
        try {
            const restored = await restoreEmailAfterFailedChange(db, {
                id: staged.id,
                tokenHash,
                email: activeEmail,
            });
            if (restored === 0) {
                console.error("Email change rollback skipped: pending state was superseded");
            }
        } catch (rollbackError) {
            console.error("Email change rollback failed", rollbackError);
        }
        throw error;
    }
    return ok(presentUser(staged));
});
