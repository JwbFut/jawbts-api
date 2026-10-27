import { Codes } from "./codes";
import {
    deliverEmail,
    EmailDeliveryError,
    escapeHtml,
    type EmailMessage,
} from "./email";
import { ApiError } from "./response";

export interface EmailChangeRequest {
    oldEmail: string;
    newEmail: string;
    at: Date;
}

export interface EmailChangeConfirmation extends EmailChangeRequest {
    token: string;
    expiresAt: Date;
}

async function send(message: EmailMessage): Promise<void> {
    try {
        await deliverEmail(message);
    } catch (error) {
        const detail =
            error instanceof EmailDeliveryError && error.status !== undefined
                ? `Email provider rejected the notification (HTTP ${error.status})`
                : error instanceof Error
                    ? error.message
                    : "Could not send the notification";
        throw new ApiError(Codes.NOTIFICATION_FAILED, {
            where: "email change notification",
            message: detail,
        });
    }
}

function htmlTable(rows: Array<[string, string]>): string {
    const body = rows
        .map(
            ([label, value]) =>
                `<tr><td style="padding:4px 12px 4px 0;color:#666">${escapeHtml(label)}</td>` +
                `<td style="padding:4px 0">${escapeHtml(value)}</td></tr>`,
        )
        .join("");
    return `<table style="border-collapse:collapse">${body}</table>`;
}

/**
 * Security notice to the OLD address, sent when a change is requested. The
 * caller must send it before the account is switched to the pending state and
 * roll back on failure, so a change request without a warning never happens.
 */
export async function sendEmailChangeRequestedNotice(
    change: EmailChangeRequest,
): Promise<void> {
    const when = change.at.toISOString();
    const text = [
        "The email address on your jawbts account is going to change.",
        "",
        `Time (UTC): ${when}`,
        `Previous email: ${change.oldEmail}`,
        `New email: ${change.newEmail}`,
        "",
        "The change takes effect only after the new address is confirmed. Until then,",
        "the account has no deliverable email and security alerts are paused.",
        "If you did not request this, revoke your sessions with POST /auth/revoke.",
    ].join("\n");
    const html = [
        "<div style=\"font-family:system-ui,sans-serif;line-height:1.5\">",
        "<p>The email address on your jawbts account is going to change.</p>",
        htmlTable([
            ["Time (UTC)", when],
            ["Previous email", change.oldEmail],
            ["New email", change.newEmail],
        ]),
        "<p style=\"color:#666\">The change takes effect only after the new address is confirmed. " +
            "Until then, the account has no deliverable email and security alerts are paused.</p>",
        "<p style=\"color:#666\">If you did not request this, revoke your sessions " +
            "with <code>POST /auth/revoke</code>.</p>",
        "</div>",
    ].join("");
    await send({
        to: change.oldEmail,
        subject: "Your jawbts email address is going to change",
        text,
        html,
    });
}

/**
 * Best-effort follow-up to the old address when a change was announced but the
 * new-address confirmation could not be sent, so the request was rolled back.
 */
export async function sendEmailChangeCancelledNotice(
    change: EmailChangeRequest,
): Promise<void> {
    const when = change.at.toISOString();
    const text = [
        "The requested email change on your jawbts account did not complete.",
        "",
        `Time (UTC): ${when}`,
        `Requested email: ${change.newEmail}`,
        "",
        "Your account email was not changed to the requested address.",
        "No action is needed.",
    ].join("\n");
    const html = [
        "<div style=\"font-family:system-ui,sans-serif;line-height:1.5\">",
        "<p>The requested email change on your jawbts account did not complete.</p>",
        htmlTable([
            ["Time (UTC)", when],
            ["Requested email", change.newEmail],
        ]),
        "<p>Your account email was not changed to the requested address. " +
            "No action is needed.</p>",
        "</div>",
    ].join("");
    await send({
        to: change.oldEmail,
        subject: "Your jawbts email change was cancelled",
        text,
        html,
    });
}

/**
 * One-time confirmation token to the NEW address. The caller must send it
 * before committing the pending state (and roll back on failure); the address
 * only becomes active through POST /auth/email/confirm.
 */
export async function sendEmailChangeConfirmation(
    change: EmailChangeConfirmation,
): Promise<void> {
    const when = change.at.toISOString();
    const expires = change.expiresAt.toISOString();
    const text = [
        "Confirm this address as the contact email for your jawbts account.",
        "",
        `Time (UTC): ${when}`,
        `Previous email: ${change.oldEmail}`,
        `Confirmation token: ${change.token}`,
        `Token expires (UTC): ${expires}`,
        "",
        "Confirm with POST /auth/email/confirm and body {\"token\":\"<token>\"}.",
        "The token can be used once.",
        "If you did not request this change, ignore this email.",
    ].join("\n");
    const html = [
        "<div style=\"font-family:system-ui,sans-serif;line-height:1.5\">",
        "<p>Confirm this address as the contact email for your jawbts account.</p>",
        htmlTable([
            ["Time (UTC)", when],
            ["Previous email", change.oldEmail],
            ["Confirmation token", change.token],
            ["Token expires (UTC)", expires],
        ]),
        "<p>Send <code>POST /auth/email/confirm</code> with " +
            "<code>{\"token\":\"&lt;token&gt;\"}</code>. The token can be used once.</p>",
        "<p style=\"color:#666\">If you did not request this change, ignore this email.</p>",
        "</div>",
    ].join("");
    await send({
        to: change.newEmail,
        subject: "Confirm your new jawbts email address",
        text,
        html,
    });
}
