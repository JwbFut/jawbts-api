import { base64UrlToBytes, bytesToBase64Url } from "./base64url";
import type { Db } from "./sessions";

/** Hidden domain used as the stored address while a change is pending. */
export const PLACEHOLDER_EMAIL_DOMAIN = "placeholder.jawbts.org";
/** A confirmation token/placeholder is valid for one day. */
export const EMAIL_CHANGE_TTL_MS = 24 * 60 * 60 * 1000;
/** Per-user cooldown between email-change requests (abuse mitigation). */
export const EMAIL_CHANGE_COOLDOWN_MS = 60_000;

const PLACEHOLDER_PREFIX = "change.";
const PLACEHOLDER_VERSION = 1;

export interface EncodedEmailChange {
    from: string;
    to: string;
    expiresAt: Date;
}

interface PlaceholderPayload {
    v: number;
    f: string;
    t: string;
    e: number;
    n: string;
}

export function isPlaceholderEmail(email: string | null | undefined): boolean {
    return Boolean(
        email && email.toLowerCase().endsWith(`@${PLACEHOLDER_EMAIL_DOMAIN}`),
    );
}

/**
 * The stored "email" while a change is pending. It is not deliverable; it
 * encodes the previous address, the requested address, the expiry and a nonce
 * so the state can be recovered without keeping the addresses in clear-text
 * columns. The whole value is hidden from API responses.
 */
export function encodeEmailChangePlaceholder(change: EncodedEmailChange): string {
    const payload: PlaceholderPayload = {
        v: PLACEHOLDER_VERSION,
        f: change.from,
        t: change.to,
        e: change.expiresAt.getTime(),
        n: crypto.randomUUID(),
    };
    const encoded = bytesToBase64Url(
        new TextEncoder().encode(JSON.stringify(payload)),
    );
    return `${PLACEHOLDER_PREFIX}${encoded}@${PLACEHOLDER_EMAIL_DOMAIN}`;
}

/** Returns null when the value is not a well-formed change placeholder. */
export function decodeEmailChangePlaceholder(
    email: string | null | undefined,
): EncodedEmailChange | null {
    if (!email || !isPlaceholderEmail(email)) {
        return null;
    }
    const local = email.slice(0, email.lastIndexOf("@"));
    if (!local.startsWith(PLACEHOLDER_PREFIX)) {
        return null;
    }
    try {
        const json = new TextDecoder().decode(
            base64UrlToBytes(local.slice(PLACEHOLDER_PREFIX.length)),
        );
        const value = JSON.parse(json) as Partial<PlaceholderPayload>;
        if (
            value.v !== PLACEHOLDER_VERSION ||
            typeof value.f !== "string" ||
            typeof value.t !== "string" ||
            typeof value.e !== "number" ||
            !Number.isFinite(value.e) ||
            value.f.length === 0 ||
            value.t.length === 0
        ) {
            return null;
        }
        return {
            from: value.f,
            to: value.t,
            expiresAt: new Date(value.e),
        };
    } catch {
        return null;
    }
}

export function generateEmailChangeToken(): string {
    return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

export async function hashEmailChangeToken(token: string): Promise<string> {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
    return Array.from(new Uint8Array(digest), (byte) =>
        byte.toString(16).padStart(2, "0"),
    ).join("");
}

/**
 * Clears the one-time token/expiry but leaves the placeholder in place — an
 * expired or conflicting change must not silently restore the old address.
 */
export async function clearEmailChangeState(
    db: Db,
    user: { id: number; emailChangeTokenHash: string | null },
): Promise<number> {
    const { count } = await db.user.updateMany({
        where: { id: user.id, emailChangeTokenHash: user.emailChangeTokenHash },
        data: { emailChangeTokenHash: null, emailChangeExpiresAt: null },
    });
    return count;
}

/**
 * Rollback for a failed request (never for expiry): restores the previous
 * address, but only if this request's token still owns the pending state.
 */
export async function restoreEmailAfterFailedChange(
    db: Db,
    user: { id: number; tokenHash: string; email: string },
): Promise<number> {
    const { count } = await db.user.updateMany({
        where: { id: user.id, emailChangeTokenHash: user.tokenHash },
        data: {
            email: user.email,
            emailChangeTokenHash: null,
            emailChangeExpiresAt: null,
            emailChangeLastSentAt: null,
        },
    });
    return count;
}
