/**
 * Wildcard CORS is safe here because auth is bearer-only (no cookies), so a
 * browser never attaches credentials automatically. Do NOT add
 * Access-Control-Allow-Credentials with a wildcard origin.
 *
 * Next handles OPTIONS automatically (204) for every route handler; this
 * config supplies the CORS headers on normal and preflight responses.
 */
export const CORS_HEADERS: Record<string, string> = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PATCH, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Content-Type, Accept",
    "Access-Control-Max-Age": "86400",
};

/** Shared OPTIONS handler: static/ISR routes do not get Next's automatic 204. */
export function corsPreflight(): Response {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
}
