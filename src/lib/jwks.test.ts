import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.parse("2026-08-03T12:00:00Z");

// In-memory fake of the Prisma `jwk` delegate.
const { fakeDb, keys, resetLock, holdLock } = vi.hoisted(() => {
    const keys: Array<{
        id: string;
        kid: string;
        publicKey: string;
        privateKey: string;
        createdAt: Date;
    }> = [];
    let idSeq = 0;
    let lockRow: { id: number; lockedUntil: Date | null } | null = null;
    const fakeDb = {
        jwk: {
            findMany: async () =>
                [...keys].sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime()),
            create: async ({ data }: { data: { kid: string; publicKey: string; privateKey: string } }) => {
                const rec = { id: String(++idSeq), createdAt: new Date(), ...data };
                keys.push(rec);
                return rec;
            },
            deleteMany: async ({ where }: { where: { id: { in: string[] } } }) => {
                const ids = new Set(where.id.in);
                let count = 0;
                for (let i = keys.length - 1; i >= 0; i--) {
                    if (ids.has(keys[i].id)) {
                        keys.splice(i, 1);
                        count++;
                    }
                }
                return { count };
            },
        },
        jwksLock: {
            createMany: async () => {
                if (!lockRow) {
                    lockRow = { id: 1, lockedUntil: null };
                    return { count: 1 };
                }
                return { count: 0 };
            },
            updateMany: async ({
                where,
                data,
            }: {
                where: {
                    id: number;
                    OR?: Array<{ lockedUntil: null } | { lockedUntil: { lt: Date } }>;
                    lockedUntil?: Date;
                };
                data: { lockedUntil: Date | null };
            }) => {
                if (!lockRow) {
                    return { count: 0 };
                }
                if (where.OR) {
                    const now = new Date();
                    const free =
                        lockRow.lockedUntil === null ||
                        lockRow.lockedUntil.getTime() < now.getTime();
                    if (!free) {
                        return { count: 0 };
                    }
                    lockRow.lockedUntil = data.lockedUntil;
                    return { count: 1 };
                }
                if (
                    where.lockedUntil &&
                    lockRow.lockedUntil?.getTime() === where.lockedUntil.getTime()
                ) {
                    lockRow.lockedUntil = null;
                    return { count: 1 };
                }
                return { count: 0 };
            },
        },
    };
    return {
        fakeDb,
        keys,
        resetLock: () => {
            lockRow = null;
        },
        holdLock: (until: Date) => {
            lockRow = { id: 1, lockedUntil: until };
        },
    };
});

vi.mock("@/lib/prisma", () => ({ getPrisma: async () => fakeDb }));
vi.mock("next/cache", () => ({ revalidatePath: vi.fn() }));

// No real RSA generation in these tests: stub key generation/export.
vi.mock("jose", async (importOriginal) => {
    const actual = await importOriginal<typeof import("jose")>();
    return {
        ...actual,
        generateKeyPair: async () => ({ publicKey: { __pub: true }, privateKey: { __priv: true } }),
        exportJWK: async (key: unknown) =>
            (key as { __pub?: boolean }).__pub
                ? { kty: "RSA", n: "N", e: "AQAB" }
                : { kty: "RSA", n: "N", e: "AQAB", d: "D" },
    };
});

import { Codes } from "./codes";
import {
    DELETE_AFTER_MS,
    JWKS_OPERATION_TIMEOUT_MS,
    MIN_SIGNING_KEY_AGE_MS,
    ROTATE_AFTER_MS,
    ROTATION_CHECK_INTERVAL_MS,
    SIGN_MAX_AGE_MS,
    getPublicJwks,
    getSigningKey,
    resetRotationCheckForTests,
    rotateKeys,
} from "./jwks";

function seedKey(ageMs: number, kid: string) {
    keys.push({
        id: String(keys.length + 1),
        kid,
        publicKey: JSON.stringify({ kty: "RSA", kid, n: "N", e: "AQAB" }),
        privateKey: JSON.stringify({ kty: "RSA", kid, n: "N", e: "AQAB", d: "D" }),
        createdAt: new Date(NOW - ageMs),
    });
}

beforeEach(() => {
    keys.length = 0;
    resetLock();
    resetRotationCheckForTests();
    vi.stubEnv("JWKS_ENCRYPTION_KEY", "test-jwks-encryption-key");
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
});

afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
});

describe("lifecycle thresholds", () => {
    it("matches the required rotation / signing / deletion windows", () => {
        expect(ROTATE_AFTER_MS).toBe(1 * DAY);
        expect(SIGN_MAX_AGE_MS).toBeCloseTo(3.2 * DAY, 0);
        expect(DELETE_AFTER_MS).toBe(5 * DAY);
    });
});

describe("JWKS operation timeout", () => {
    it("waits for a busy lease and throws after the timeout", async () => {
        holdLock(new Date(NOW + 10 * 60_000));
        const promise = getSigningKey();
        const assertion = expect(promise).rejects.toThrow(/timed out/);
        await vi.advanceTimersByTimeAsync(JWKS_OPERATION_TIMEOUT_MS);
        await assertion;
    });

    it("fails instead of waiting forever on a hung database call", async () => {
        vi.spyOn(fakeDb.jwk, "findMany").mockImplementation(
            () => new Promise(() => {}),
        );
        const promise = getSigningKey();
        // Attach the rejection handler before advancing timers, otherwise the
        // rejection is observed before the assertion is wired up.
        const assertion = expect(promise).rejects.toThrow(/timed out/);
        await vi.advanceTimersByTimeAsync(JWKS_OPERATION_TIMEOUT_MS);
        await assertion;
    });
});

describe("rotation check throttling", () => {
    it("runs at most once per 30 minutes", async () => {
        seedKey(6 * DAY, "expired");
        seedKey(0.5 * DAY, "fresh");
        await rotateKeys();
        expect(keys.map((k) => k.kid)).not.toContain("expired");

        // A second check inside the interval is skipped, even though a key is
        // now old enough to delete.
        seedKey(6 * DAY, "expired-2");
        await rotateKeys();
        expect(keys.map((k) => k.kid)).toContain("expired-2");

        vi.advanceTimersByTime(ROTATION_CHECK_INTERVAL_MS);
        await rotateKeys();
        expect(keys.map((k) => k.kid)).not.toContain("expired-2");
    });

    it("shares one in-flight check between concurrent callers", async () => {
        const spy = vi.spyOn(fakeDb.jwk, "findMany");
        await Promise.all([rotateKeys(), rotateKeys(), rotateKeys()]);
        expect(spy).toHaveBeenCalledTimes(1);
        expect(keys).toHaveLength(1);
    });

    it("retries on the next call when a check fails", async () => {
        const spy = vi.spyOn(fakeDb.jwk, "findMany");
        spy.mockRejectedValueOnce(new Error("db down"));
        await expect(rotateKeys()).rejects.toThrow("db down");
        await rotateKeys();
        expect(spy).toHaveBeenCalledTimes(2);
        expect(keys).toHaveLength(1);
    });
});

describe("rotateKeys", () => {
    it("generates a key when none exist", async () => {
        await rotateKeys();
        expect(keys).toHaveLength(1);
    });

    it("keeps the key when the newest is younger than 1 day", async () => {
        seedKey(0.5 * DAY, "fresh");
        await rotateKeys();
        expect(keys).toHaveLength(1);
        expect(keys[0].kid).toBe("fresh");
    });

    it("generates a new key when the newest is older than 1 day", async () => {
        seedKey(1.5 * DAY, "oldish");
        await rotateKeys();
        expect(keys).toHaveLength(2);
    });

    it("deletes keys older than 5 days", async () => {
        seedKey(6 * DAY, "expired");
        seedKey(0.5 * DAY, "fresh");
        await rotateKeys();
        const kids = keys.map((k) => k.kid);
        expect(kids).not.toContain("expired");
        expect(kids).toContain("fresh");
    });
});

describe("getSigningKey", () => {
    it("returns the newest key when it is fresh", async () => {
        seedKey(0.5 * DAY, "fresh");
        const key = await getSigningKey();
        expect(key.kid).toBe("fresh");
    });

    it("never returns a key older than the 3.2 day signing window", async () => {
        seedKey(4 * DAY, "stale");
        seedKey(2 * DAY, "usable");
        const key = await getSigningKey();
        expect(NOW - key.createdAt.getTime()).toBeLessThanOrEqual(SIGN_MAX_AGE_MS);
        expect(key.kid).toBe("usable");
    });

    it("does not sign with a key newer than the publish window", async () => {
        seedKey(60_000, "too-new");
        await expect(getSigningKey()).rejects.toMatchObject({
            code: Codes.NO_SIGNING_KEY,
        });
    });

    it("uses an older eligible key while the new key is still publishing", async () => {
        seedKey(60_000, "too-new");
        seedKey(2 * DAY, "older");
        const key = await getSigningKey();
        expect(key.kid).toBe("older");
    });
});

describe("getPublicJwks", () => {
    it("exposes only keys that have not been deleted", async () => {
        seedKey(6 * DAY, "expired");
        seedKey(2 * DAY, "mid");
        const jwks = await getPublicJwks();
        const kids = jwks.keys.map((k) => k.kid);
        expect(kids).not.toContain("expired");
        expect(kids).toContain("mid");
    });

    it("bootstraps a key when the table is empty", async () => {
        const jwks = await getPublicJwks();
        expect(jwks.keys).toHaveLength(1);
    });
});

describe("private key encryption at rest", () => {
    it("stores a generated key encrypted and decrypts it for signing", async () => {
        await rotateKeys();
        expect(keys).toHaveLength(1);
        expect(keys[0].privateKey.startsWith("enc:v1:")).toBe(true);
        expect(keys[0].privateKey).not.toContain("\"d\"");

        vi.advanceTimersByTime(MIN_SIGNING_KEY_AGE_MS);
        const signing = await getSigningKey();
        expect(JSON.parse(signing.privateKey)).toMatchObject({ kty: "RSA", d: "D" });
    });

    it("reads legacy plaintext keys (migration shim)", async () => {
        seedKey(0.5 * DAY, "legacy");
        const signing = await getSigningKey();
        expect(signing.kid).toBe("legacy");
        expect(JSON.parse(signing.privateKey)).toMatchObject({ d: "D" });
    });

    it("fails closed when the stored key cannot be decrypted", async () => {
        await rotateKeys();
        vi.advanceTimersByTime(MIN_SIGNING_KEY_AGE_MS);
        // Simulate rotating JWKS_ENCRYPTION_KEY: the stored key is no longer
        // decryptable. Do not silently sign with an unpublished replacement.
        vi.stubEnv("JWKS_ENCRYPTION_KEY", "a-different-encryption-key");
        await expect(getSigningKey()).rejects.toMatchObject({
            code: Codes.NO_SIGNING_KEY,
        });
        expect(keys).toHaveLength(1);
    });

    it("fails closed when JWKS_ENCRYPTION_KEY is missing", async () => {
        vi.stubEnv("JWKS_ENCRYPTION_KEY", "");
        await expect(rotateKeys()).rejects.toThrow("JWKS_ENCRYPTION_KEY is not set");
    });
});
