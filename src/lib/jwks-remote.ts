import { createRemoteJWKSet, type JWTVerifyGetKey } from "jose";

export const JWKS_PATH = "/.well-known/jwks.json";
/** Abort a slow JWKS subrequest instead of hanging the verification. */
export const JWKS_TIMEOUT_MS = 60_000;
/** jose reuses a fetched JWKS for this long before refetching. */
export const JWKS_CACHE_MAX_AGE_MS = 60_000;
/**
 * Minimum gap between "unknown kid" refetches. jose refreshes on its own when
 * a token names a key it has not seen (rotation), but this floor keeps a
 * forged kid from turning the unauthenticated endpoint into a fetch
 * amplifier.
 */
export const JWKS_COOLDOWN_MS = 5_000;

export const REMOTE_JWKS_MAX_ENTRIES = 16;
export const REMOTE_JWKS_ENTRY_TTL_MS = 10 * 60_000;

interface RemoteEntry {
    set: JWTVerifyGetKey;
    expiresAt: number;
}

// One remote key set per origin (custom domains included), per runtime
// instance. Bounded so an arbitrary-host caller cannot grow it forever.
const remoteJwks = new Map<string, RemoteEntry>();

function parseHttpOrigin(value: string): string {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
        throw new Error("JWKS_ORIGIN must use http: or https:");
    }
    return url.origin;
}

export function getRemoteJwks(req: Request): JWTVerifyGetKey {
    const configured = process.env.JWKS_ORIGIN?.trim();
    if (!configured && process.env.NODE_ENV === "production") {
        // Never derive the JWKS origin from the Host header in production:
        // /auth/verify is unauthenticated, so that would be an SSRF vector.
        throw new Error("JWKS_ORIGIN is required in production");
    }
    const origin = configured
        ? parseHttpOrigin(configured)
        : parseHttpOrigin(new URL(req.url).origin);

    const now = Date.now();
    for (const [key, entry] of remoteJwks) {
        if (entry.expiresAt <= now) {
            remoteJwks.delete(key);
        }
    }
    const existing = remoteJwks.get(origin);
    if (existing) {
        existing.expiresAt = now + REMOTE_JWKS_ENTRY_TTL_MS;
        return existing.set;
    }
    if (remoteJwks.size >= REMOTE_JWKS_MAX_ENTRIES) {
        const oldest = remoteJwks.keys().next().value;
        if (oldest !== undefined) {
            remoteJwks.delete(oldest);
        }
    }
    const set = createRemoteJWKSet(new URL(JWKS_PATH, origin), {
        timeoutDuration: JWKS_TIMEOUT_MS,
        cacheMaxAge: JWKS_CACHE_MAX_AGE_MS,
        cooldownDuration: JWKS_COOLDOWN_MS,
    });
    remoteJwks.set(origin, {
        set,
        expiresAt: now + REMOTE_JWKS_ENTRY_TTL_MS,
    });
    return set;
}

/** Test-only hook: forget the per-origin remote key sets. */
export function resetRemoteJwksForTests(): void {
    remoteJwks.clear();
}
