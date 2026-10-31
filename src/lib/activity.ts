import { Codes } from "./codes";
import { isPlaceholderEmail } from "./email-change";
import { deliverEmail, EmailDeliveryError, escapeHtml } from "./email";
import { ApiError } from "./response";
import type { Db } from "./sessions";

/**
 * A (IP, user agent) fingerprint is "known" while a hash of it was recorded
 * within this window. Rows older than the window never suppress an alert.
 */
export const ACTIVITY_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
/** Bumped if the hash input ever needs to change (invalidates old hashes). */
export const ACTIVITY_HASH_VERSION = 1;
// Re-exported for compatibility with tests/importers of this module.
export { DEFAULT_ALERT_FROM, RESEND_ENDPOINT, RESEND_TIMEOUT_MS } from "./email";

export type ActivityKind = "login" | "refresh";

export interface ActivityAlert {
    to: string;
    ip: string;
    userAgent: string;
    kind: ActivityKind;
    at: Date;
}

export interface ActivityEvent {
    userId: number;
    email: string | null | undefined;
    ip: string;
    userAgent: string;
    kind: ActivityKind;
}

/** Canonical, unambiguous encoding of the values that get hashed. */
export function activityHashInput(ip: string, userAgent: string): string {
    return JSON.stringify({ v: ACTIVITY_HASH_VERSION, ip, userAgent });
}

/**
 * Deployment-wide pepper mixed into every fingerprint. It is not a per-row
 * salt (lookups must stay deterministic) but it makes a leaked hash table
 * useless without the secret. Required: a missing value fails closed.
 */
export function activityHashSalt(): string {
    const salt = process.env.ACTIVITY_HASH_SALT?.trim();
    if (!salt) {
        throw new Error("ACTIVITY_HASH_SALT is not set");
    }
    return salt;
}

export async function sha512Hex(input: string): Promise<string> {
    const digest = await crypto.subtle.digest("SHA-512", new TextEncoder().encode(input));
    return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Salted SHA-512 fingerprint of the request's IP + user agent (128 hex chars). */
export async function hashActivity(ip: string, userAgent: string): Promise<string> {
    return sha512Hex(`${activityHashSalt()}\n${activityHashInput(ip, userAgent)}`);
}

function alertCopy(kind: ActivityKind): { subject: string; intro: string } {
    if (kind === "login") {
        return {
            subject: "New login to your jawbts account",
            intro: "A new device signed in to your jawbts account.",
        };
    }
    return {
        subject: "New activity on your jawbts account",
        intro: "A new device used a refresh token on your jawbts account.",
    };
}

/** Renders the alert body; exported for tests. */
export function buildActivityAlert(alert: ActivityAlert): {
    subject: string;
    text: string;
    html: string;
} {
    const copy = alertCopy(alert.kind);
    const when = alert.at.toISOString();
    const text = [
        copy.intro,
        "",
        `Time (UTC): ${when}`,
        `IP address: ${alert.ip}`,
        `User agent: ${alert.userAgent}`,
        "",
        "If this was you, no action is needed.",
        "It's suggested to delete this email.",
    ].join("\n");
    const row = (label: string, value: string) =>
        `<tr><td style="padding:4px 12px 4px 0;color:#666">${escapeHtml(label)}</td>` +
        `<td style="padding:4px 0">${escapeHtml(value)}</td></tr>`;
    const html = [
        "<div style=\"font-family:system-ui,sans-serif;line-height:1.5\">",
        `<p>${escapeHtml(copy.intro)}</p>`,
        "<table style=\"border-collapse:collapse\">",
        row("Time (UTC)", when),
        row("IP address", alert.ip),
        row("User agent", alert.userAgent),
        "</table>",
        "<p style=\"color:#666\">If this was you, no action is needed. If this wasn't you, " +
        "it's suggested to delete this email.</p>",
        "</div>",
    ].join("");
    return { subject: copy.subject, text, html };
}

/**
 * Sends one activity alert through Resend. Any failure (missing key,
 * unreachable provider, non-2xx response) throws ACTIVITY_ALERT_FAILED, which
 * the caller converts into a failed login/refresh.
 */
export async function sendActivityAlert(alert: ActivityAlert): Promise<void> {
    const { subject, text, html } = buildActivityAlert(alert);
    try {
        await deliverEmail({ to: alert.to, subject, text, html });
    } catch (error) {
        const message =
            error instanceof EmailDeliveryError && error.status !== undefined
                ? `Email provider rejected the alert (HTTP ${error.status})`
                : error instanceof Error
                    ? error.message
                    : "Could not send the alert";
        throw new ApiError(Codes.ACTIVITY_ALERT_FAILED, {
            where: "activity alert",
            message,
        });
    }
}

/**
 * Records a login/refresh fingerprint and alerts the account owner when the
 * fingerprint has not been seen in the last 7 days. The row is written only
 * after a successful send (or when no email is on file), so a failed alert —
 * which fails the request — is attempted again on the next login/refresh.
 */
export async function recordActivity(db: Db, event: ActivityEvent): Promise<void> {
    const email = event.email?.trim();
    // A placeholder means the account is mid email change and has no
    // deliverable address. Record nothing: otherwise the first login after
    // confirmation from that device would be treated as known and never alert.
    if (isPlaceholderEmail(email)) {
        return;
    }
    const hash = await hashActivity(event.ip, event.userAgent);
    const since = new Date(Date.now() - ACTIVITY_WINDOW_MS);
    // Retention: a row older than the window can never suppress an alert, so
    // drop it. Best-effort: a cleanup failure must not block authentication
    // (the lookup below still only considers the window).
    try {
        await db.activityHash.deleteMany({ where: { createdAt: { lt: since } } });
    } catch (error) {
        console.error("Activity retention cleanup failed", error);
    }
    const known = await db.activityHash.findFirst({
        where: { userId: event.userId, hash, createdAt: { gte: since } },
        select: { id: true },
    });
    if (!known && email) {
        await sendActivityAlert({
            to: email,
            ip: event.ip,
            userAgent: event.userAgent,
            kind: event.kind,
            at: new Date(),
        });
    }
    await db.activityHash.create({ data: { userId: event.userId, hash } });
}
