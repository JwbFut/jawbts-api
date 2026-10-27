import { api, corsPreflight } from "@/lib/api";
import { getPublicJwks } from "@/lib/jwks";

/**
 * Vercel cron requests this path daily (see vercel.json), so the lazy JWKS
 * rotation check runs even when there is no user traffic. The 60 s cache keeps
 * ordinary verification requests cheap.
 */
export const revalidate = 60;

export const OPTIONS = corsPreflight;

// Standard JWKS document. Returned raw (not wrapped in the app envelope) so
// standard JOSE clients can consume it directly. Runs the rotation check.
export const GET = api(async () => {
    const jwks = await getPublicJwks();
    return Response.json(jwks);
});
