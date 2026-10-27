import { exportJWK, generateKeyPair, type JWK } from "jose";
import { revalidatePath } from "next/cache";
import { Codes } from "./codes";
import { ApiError } from "./response";
import { decryptPrivateKey, encryptPrivateKey } from "./key-vault";
import { getPrisma } from "./prisma";

// RSA-4096 keys; JWTs signed with RS256 (RSA PKCS#1 v1.5 + SHA-256).
export const JWT_ALG = "RS256";
export const JWT_ISSUER = "jawbts-api";
const MODULUS_LENGTH = 4096;

// Key lifecycle thresholds.
const DAY_MS = 24 * 60 * 60 * 1000;
/** Never let a hung Neon/WebCrypto call hold the JWKS path for Vercel's limit. */
export const JWKS_OPERATION_TIMEOUT_MS = 60_000;

function withTimeout<T>(promise: Promise<T>, label: string): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
        timer = setTimeout(
            () =>
                reject(
                    new Error(
                        `${label} timed out after ${JWKS_OPERATION_TIMEOUT_MS}ms`,
                    ),
                ),
            JWKS_OPERATION_TIMEOUT_MS,
        );
    });
    // If either side loses the race, mark its late rejection as handled so
    // it cannot surface as an unhandled rejection.
    timeout.catch(() => {});
    promise.catch(() => {});
    return Promise.race([promise, timeout]).finally(() => {
        if (timer) {
            clearTimeout(timer);
        }
    });
}
export const ROTATE_AFTER_MS = 1 * DAY_MS; // newest key older than 1 day -> mint a new one
export const SIGN_MAX_AGE_MS = 3.2 * DAY_MS; // a signing key must be issued within 3.2 days
/** A key must be published for this long before it is used to sign. */
export const MIN_SIGNING_KEY_AGE_MS = 2 * 60_000;
export const DELETE_AFTER_MS = 5 * DAY_MS; // delete keys older than 5 days
/** GitHub-login JWTs are short-lived so revocation/scope changes take effect quickly. */
export const GITHUB_TOKEN_TTL_SECONDS = 10 * 60;
/** Delegated JWTs keep their 1-day lifetime for integrations. */
export const DELEGATED_TOKEN_TTL_SECONDS = 24 * 60 * 60;

export interface StoredKey {
    id: string;
    kid: string;
    publicKey: string;
    privateKey: string;
    createdAt: Date;
}

function ageMs(createdAt: Date, now: number): number {
    return now - createdAt.getTime();
}

let publicJwksCache: { keys: JWK[]; expiresAt: number } | null = null;
const PUBLIC_JWKS_CACHE_MS = 60_000;

function invalidateJwksCache(reason: string): void {
    publicJwksCache = null;
    try {
        revalidatePath("/.well-known/jwks.json");
    } catch (error) {
        // Outside a request/route context this is expected (tests, CLI); the
        // route's periodic revalidate will eventually pick the key up.
        console.error(`JWKS cache revalidation failed (${reason})`, error);
    }
}

async function generateKey(db: Awaited<ReturnType<typeof getPrisma>>): Promise<StoredKey> {
    const { publicKey, privateKey } = await generateKeyPair(JWT_ALG, {
        modulusLength: MODULUS_LENGTH,
        // The private key is persisted as a JWK, so it must be exportable.
        extractable: true,
    });
    const publicJwk: JWK = await exportJWK(publicKey);
    const privateJwk: JWK = await exportJWK(privateKey);
    const kid = crypto.randomUUID();
    publicJwk.kid = kid;
    publicJwk.alg = JWT_ALG;
    publicJwk.use = "sig";
    privateJwk.kid = kid;
    const created = await db.jwk.create({
        data: {
            kid,
            publicKey: JSON.stringify(publicJwk),
            // Private keys are encrypted at rest; only the public JWK is
            // exposed through /.well-known/jwks.json.
            privateKey: await encryptPrivateKey(JSON.stringify(privateJwk)),
        },
    });
    invalidateJwksCache("new key");
    return created;
}

/** Rotation checks are throttled per runtime instance. */
export const ROTATION_CHECK_INTERVAL_MS = 30 * 60_000;
const ROTATION_LOCK_ID = 1;
/** A crashed holder must not block rotation forever. */
const ROTATION_LOCK_TTL_MS = 2 * JWKS_OPERATION_TIMEOUT_MS;

let lastRotationCheckAt = 0;
let rotationInFlight: Promise<boolean> | null = null;

async function acquireRotationLock(
    db: Awaited<ReturnType<typeof getPrisma>>,
): Promise<Date | null> {
    await db.jwksLock.createMany({
        data: [{ id: ROTATION_LOCK_ID }],
        skipDuplicates: true,
    });
    const now = new Date();
    const lockedUntil = new Date(now.getTime() + ROTATION_LOCK_TTL_MS);
    const { count } = await db.jwksLock.updateMany({
        where: {
            id: ROTATION_LOCK_ID,
            OR: [{ lockedUntil: null }, { lockedUntil: { lt: now } }],
        },
        data: { lockedUntil },
    });
    return count === 1 ? lockedUntil : null;
}

async function releaseRotationLock(
    db: Awaited<ReturnType<typeof getPrisma>>,
    lockedUntil: Date,
): Promise<void> {
    await db.jwksLock.updateMany({
        where: { id: ROTATION_LOCK_ID, lockedUntil },
        data: { lockedUntil: null },
    });
}

async function withRotationLease<T>(
    db: Awaited<ReturnType<typeof getPrisma>>,
    run: () => Promise<T>,
): Promise<T> {
    const deadline = Date.now() + JWKS_OPERATION_TIMEOUT_MS;
    let lock = await acquireRotationLock(db);
    while (!lock) {
        if (Date.now() >= deadline) {
            throw new Error("JWKS rotation lease timed out");
        }
        await new Promise((resolve) => setTimeout(resolve, 250));
        lock = await acquireRotationLock(db);
    }
    try {
        return await run();
    } finally {
        await releaseRotationLock(db, lock).catch((error: unknown) => {
            console.error("JWKS rotation lock release failed", error);
        });
    }
}

export async function rotateKeys(): Promise<boolean> {
    if (Date.now() - lastRotationCheckAt < ROTATION_CHECK_INTERVAL_MS) {
        return false;
    }
    if (rotationInFlight) {
        return withTimeout(rotationInFlight, "JWKS rotation");
    }
    // Claim the local single-flight slot before any await so concurrent
    // callers share this check instead of each polling the DB lease.
    const check = (async () => {
        const db = await getPrisma();
        return withRotationLease(db, () => runRotationCheck(db));
    })();
    rotationInFlight = check;
    try {
        return await withTimeout(check, "JWKS rotation");
    } finally {
        rotationInFlight = null;
    }
}

async function runRotationCheck(
    db: Awaited<ReturnType<typeof getPrisma>>,
): Promise<boolean> {
    const now = Date.now();
    const keys = await db.jwk.findMany({ orderBy: { createdAt: "desc" } });
    const expiredIds = keys
        .filter((k) => ageMs(k.createdAt, now) > DELETE_AFTER_MS)
        .map((k) => k.id);
    if (expiredIds.length > 0) {
        await db.jwk.deleteMany({ where: { id: { in: expiredIds } } });
        invalidateJwksCache("expired keys");
    }
    const fresh = keys.filter((k) => ageMs(k.createdAt, now) <= DELETE_AFTER_MS);
    const newest = fresh[0];
    let changed = expiredIds.length > 0;
    if (!newest || ageMs(newest.createdAt, now) > ROTATE_AFTER_MS) {
        await generateKey(db);
        changed = true;
    }
    lastRotationCheckAt = Date.now();
    return changed;
}

/** Test-only hook: forget the throttle state. */
export function resetRotationCheckForTests(): void {
    lastRotationCheckAt = 0;
    rotationInFlight = null;
    publicJwksCache = null;
}

/**
 * The key used to sign: the newest key that has already been published for at
 * least MIN_SIGNING_KEY_AGE_MS and is still within SIGN_MAX_AGE. Rotation keeps
 * an older eligible key available while the replacement propagates to caches.
 * If none exists, fails closed with Codes.NO_SIGNING_KEY instead of signing
 * with a key verifiers may not have seen yet.
 */
export async function getSigningKey(): Promise<StoredKey> {
    return withTimeout(getSigningKeyInner(), "JWKS signing key");
}

async function getSigningKeyInner(): Promise<StoredKey> {
    const db = await getPrisma();
    await rotateKeys();
    const now = Date.now();
    const keys = await db.jwk.findMany({ orderBy: { createdAt: "desc" } });
    // Publish-before-sign: a key younger than MIN_SIGNING_KEY_AGE_MS may not
    // yet be visible in another instance's public-JWKS cache or a verifier's
    // remote-JWKS cache. Keep signing with an older eligible key during the
    // overlap, and fail closed if there is none.
    const eligible = keys.filter((k) => {
        const age = ageMs(k.createdAt, now);
        return age >= MIN_SIGNING_KEY_AGE_MS && age <= SIGN_MAX_AGE_MS;
    });
    for (const key of eligible) {
        try {
            // `key.privateKey` is encrypted at rest; callers receive usable JWK JSON.
            return { ...key, privateKey: await decryptPrivateKey(key.privateKey) };
        } catch (error) {
            // A rotated JWKS_ENCRYPTION_KEY makes old rows undecryptable. Try
            // other eligible keys; never invent an unpublished signing key.
            console.error("JWKS private key cannot be decrypted; trying older key", error);
        }
    }
    throw new ApiError(Codes.NO_SIGNING_KEY, {
        message: "No signing key has been published for at least 2 minutes",
    });
}

/** Public JWKS document: every key not yet deleted, newest first. */
export async function getPublicJwks(): Promise<{ keys: JWK[] }> {
    if (publicJwksCache && publicJwksCache.expiresAt > Date.now()) {
        return { keys: publicJwksCache.keys };
    }
    const result = await withTimeout(getPublicJwksInner(), "JWKS document");
    publicJwksCache = {
        keys: result.keys,
        expiresAt: Date.now() + PUBLIC_JWKS_CACHE_MS,
    };
    return result;
}

async function getPublicJwksInner(): Promise<{ keys: JWK[] }> {
    const db = await getPrisma();
    await rotateKeys();
    const now = Date.now();
    let keys = await db.jwk.findMany({ orderBy: { createdAt: "desc" } });
    let fresh = keys.filter((k) => ageMs(k.createdAt, now) <= DELETE_AFTER_MS);
    if (fresh.length === 0) {
        // Bootstrap on a fresh/empty database under the same lease.
        await withRotationLease(db, async () => {
            const current = await db.jwk.findMany({ orderBy: { createdAt: "desc" } });
            const currentNow = Date.now();
            if (!current.some((k) => ageMs(k.createdAt, currentNow) <= DELETE_AFTER_MS)) {
                await generateKey(db);
            }
        });
        keys = await db.jwk.findMany({ orderBy: { createdAt: "desc" } });
        fresh = keys.filter((k) => ageMs(k.createdAt, now) <= DELETE_AFTER_MS);
    }
    return { keys: fresh.map((k) => JSON.parse(k.publicKey) as JWK) };
}
