/** Shared Resend delivery for activity alerts and account notifications. */
export const RESEND_ENDPOINT = "https://api.resend.com/emails";
export const DEFAULT_ALERT_FROM = "Api Bot <api-bot@noreply.jawbts.org>";
export const RESEND_TIMEOUT_MS = 10_000;

export interface EmailMessage {
    to: string;
    subject: string;
    text: string;
    html: string;
}

/** Delivery failure with a safe message (never contains the API key). */
export class EmailDeliveryError extends Error {
    constructor(
        message: string,
        readonly status?: number,
    ) {
        super(message);
        this.name = "EmailDeliveryError";
    }
}

export function escapeHtml(value: string): string {
    return value
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll("\"", "&quot;")
        .replaceAll("'", "&#39;");
}

export async function deliverEmail(message: EmailMessage): Promise<void> {
    const apiKey = process.env.RESEND_API_KEY?.trim();
    if (!apiKey) {
        throw new EmailDeliveryError(
            "Email delivery is not configured (RESEND_API_KEY is not set)",
        );
    }
    const from = process.env.RESEND_FROM?.trim() || DEFAULT_ALERT_FROM;
    let response: Response;
    try {
        response = await fetch(RESEND_ENDPOINT, {
            method: "POST",
            headers: {
                Authorization: `Bearer ${apiKey}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                from,
                to: [message.to],
                subject: message.subject,
                text: message.text,
                html: message.html,
            }),
            signal: AbortSignal.timeout(RESEND_TIMEOUT_MS),
        });
    } catch (error) {
        console.error("Email provider unreachable", error);
        throw new EmailDeliveryError("Could not reach the email provider");
    }
    if (!response.ok) {
        // Do not log the provider body: it can echo the recipient address.
        console.error(`Email provider returned HTTP ${response.status}`);
        throw new EmailDeliveryError(
            `Email provider rejected the email (HTTP ${response.status})`,
            response.status,
        );
    }
}
