import { exportJWK, generateKeyPair, importJWK, jwtVerify, SignJWT, type JWK } from "jose";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { request } from "@/test/request";
import { sha256Hex } from "@/lib/sessions";
import { POST as issueToken } from "./token/route";

// In-memory Prisma stand-in: user lookup + JWKS/JWK storage.
const { fakeDb, users, keys, sessions, loginSessions } = vi.hoisted(() => {
    type UserRow = {
        id: number;
        name: string;
        email: string;
        githubId: string;
        permissions: string[];
    };
    type JwkRow = {
        id: string;
        kid: string;
        publicKey: string;
        privateKey: string;
        createdAt: Date;
    };
    type SessionRow = {
        id: string;
        userId: number;
        type: string;
        refreshTokenHash: string | null;
        previousRefreshTokenHash: string | null;
        permissions: string[];
        label: string | null;
        parentId: string | null;
        expiresAt: Date;
        createdAt: Date;
        updatedAt: Date;
    };
    const users: UserRow[] = [];
    const keys: JwkRow[] = [];
    const sessions: SessionRow[] = [];
    const loginSessions: Array<{
        id: string;
        userId: number;
        type: string;
        expiresAt: Date;
    }> = [];
    let seq = 0;
    const jwksLock = {
        createMany: async () => ({ count: 0 }),
        updateMany: async () => ({ count: 1 }),
    };
    const fakeDb = {
        jwksLock,
        user: {
            update: async () => ({}),
            findMany: async ({ where }: { where?: { name?: { equals?: string } } } = {}) => {
                const name = where?.name?.equals;
                if (name === undefined) {
                    return [...users];
                }
                return users.filter(
                    (user) => user.name.toLowerCase() === name.toLowerCase(),
                );
            },
        },
        session: {
            deleteMany: async () => ({ count: 0 }),
            findUnique: async ({ where }: { where: { id: string } }) =>
                loginSessions.find((row) => row.id === where.id) ??
                sessions.find((row) => row.id === where.id) ??
                null,
            count: async ({
                where,
            }: {
                where: { userId: number; type: string; expiresAt: { gte: Date } };
            }) =>
                sessions.filter(
                    (row) =>
                        row.userId === where.userId &&
                        row.type === where.type &&
                        row.expiresAt >= where.expiresAt.gte,
                ).length,
            create: async ({ data }: { data: Partial<SessionRow> }) => {
                const record: SessionRow = {
                    id: `s${++seq}`,
                    userId: 0,
                    type: "",
                    refreshTokenHash: null,
                    previousRefreshTokenHash: null,
                    permissions: [],
                    label: null,
                    parentId: null,
                    expiresAt: new Date(),
                    createdAt: new Date(),
                    updatedAt: new Date(),
                    ...data,
                };
                sessions.push(record);
                return record;
            },
        },
        $transaction: async <T,>(fn: (tx: unknown) => Promise<T>): Promise<T> => fn(fakeDb),
        jwk: {
            findMany: async () =>
                [...keys].sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime()),
            create: async ({ data }: { data: Omit<JwkRow, "id" | "createdAt"> }) => {
                const record: JwkRow = { id: `k${++seq}`, createdAt: new Date(), ...data };
                keys.push(record);
                return record;
            },
            deleteMany: async () => ({ count: 0 }),
        },
    };
    return { fakeDb, users, keys, sessions, loginSessions };
});

vi.mock("@/lib/prisma", () => ({
    getPrisma: async () => fakeDb,
    supportsTransactions: () => true,
}));

let privateJwk: JWK;

beforeAll(async () => {
    const { publicKey, privateKey } = await generateKeyPair("RS256", {
        modulusLength: 2048,
        extractable: true,
    });
    const pub = await exportJWK(publicKey);
    const priv = await exportJWK(privateKey);
    const kid = crypto.randomUUID();
    pub.kid = kid;
    pub.alg = "RS256";
    pub.use = "sig";
    priv.kid = kid;
    keys.push({
        id: "k-seed",
        kid,
        publicKey: JSON.stringify(pub),
        privateKey: JSON.stringify(priv),
        createdAt: new Date(Date.now() - 5 * 60_000),
    });
    privateJwk = priv;
}, 30000);

beforeEach(() => {
    users.length = 0;
    sessions.length = 0;
    loginSessions.length = 0;
    loginSessions.push({
        id: "github-session",
        userId: 1,
        type: "REFRESH_TOKEN",
        expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
    });
    users.push({
        id: 1,
        name: "alice",
        email: "alice@example.com",
        githubId: "111",
        permissions: ["issue_tokens", "play_sequence_override"],
    });
});

function post(body: unknown, token?: string) {
    return request("http://localhost/auth/token", {
        method: "POST",
        body: JSON.stringify(body),
        headers: token === undefined ? {} : { authorization: `Bearer ${token}` },
    });
}

async function mintRequestToken(opts: {
    scope: string[];
    sid?: string;
}): Promise<string> {
    const key = await importJWK(privateJwk, "RS256");
    return new SignJWT({ scope: opts.scope, sid: opts.sid ?? "github-session" })
        .setProtectedHeader({ alg: "RS256", kid: String(privateJwk.kid) })
        .setIssuer("jawbts-api")
        .setSubject("alice")
        .setIssuedAt()
        .setExpirationTime(Math.floor(Date.now() / 1000) + 3600)
        .sign(key);
}

describe("POST /auth/token (permission-gated issuance)", () => {
    it("requires a bearer token", async () => {
        const res = await issueToken(post({ scope: ["play_sequence_override"] }), {});
        expect(res.status).toBe(401);
        expect((await res.json()).code).toBe(10002);
    });

    it("rejects a token without the issue_tokens permission", async () => {
        const token = await mintRequestToken({ scope: ["api"] });
        const res = await issueToken(post({ scope: ["play_sequence_override"] }, token), {});
        expect(res.status).toBe(403);
        expect((await res.json()).code).toBe(10007);
    });

    it("rejects a delegated-style token (no issue_tokens) outright", async () => {
        const token = await mintRequestToken({ scope: ["play_sequence_override"] });
        const res = await issueToken(post({ scope: ["play_sequence_override"] }, token), {});
        expect(res.status).toBe(403);
        expect((await res.json()).code).toBe(10007);
    });

    it("re-checks issue_tokens in the database (the user can lose it)", async () => {
        users[0].permissions = ["play_sequence_override"];
        const token = await mintRequestToken({ scope: ["issue_tokens"] });
        const res = await issueToken(post({ scope: ["play_sequence_override"] }, token), {});
        expect(res.status).toBe(403);
        expect((await res.json()).code).toBe(10007);
    });

    it("rejects unknown permissions", async () => {
        const token = await mintRequestToken({ scope: ["issue_tokens"] });
        const res = await issueToken(post({ scope: ["root"] }, token), {});
        expect(res.status).toBe(400);
        expect((await res.json()).code).toBe(10001);
    });

    it("never delegates issue_tokens", async () => {
        const token = await mintRequestToken({ scope: ["issue_tokens"] });
        const res = await issueToken(post({ scope: ["issue_tokens"] }, token), {});
        expect(res.status).toBe(403);
        expect((await res.json()).code).toBe(10003);
    });

    it("never delegates the internal api scope", async () => {
        const token = await mintRequestToken({ scope: ["issue_tokens"] });
        const res = await issueToken(post({ scope: ["api"] }, token), {});
        expect(res.status).toBe(403);
        expect((await res.json()).code).toBe(10003);
    });

    it("rejects a permission the user does not hold", async () => {
        users[0].permissions = ["issue_tokens"];
        const token = await mintRequestToken({ scope: ["issue_tokens"] });
        const res = await issueToken(post({ scope: ["play_sequence_override"] }, token), {});
        expect(res.status).toBe(403);
        expect((await res.json()).code).toBe(10007);
    });

    it("rejects an empty scope", async () => {
        const token = await mintRequestToken({ scope: ["issue_tokens"] });
        const res = await issueToken(post({ scope: [] }, token), {});
        expect(res.status).toBe(400);
        expect((await res.json()).code).toBe(10001);
    });

    it("mints a short-lived, subject-bound token with the requested scope", async () => {
        const requestToken = await mintRequestToken({ scope: ["issue_tokens", "api"] });
        const res = await issueToken(
            post({ scope: ["play_sequence_override"] }, requestToken),
            {},
        );
        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.data.scope).toEqual(["play_sequence_override"]);
        expect(body.data.expiresIn).toBe(86400);

        const key = await importJWK(JSON.parse(keys[0].publicKey), "RS256");
        const { payload } = await jwtVerify(body.data.token, key, { issuer: "jawbts-api" });
        expect(payload.sub).toBe("alice");
        expect(payload.scope).toEqual(["play_sequence_override"]);
        expect((payload.exp as number) - (payload.iat as number)).toBe(86400);
    });

    it("creates a manageable delegated session with its own refresh token", async () => {
        const requestToken = await mintRequestToken({ scope: ["issue_tokens"] });
        const before = Date.now();
        const res = await issueToken(
            post({ scope: ["play_sequence_override"] }, requestToken),
            {},
        );
        expect(res.status).toBe(200);
        const body = await res.json();

        expect(sessions).toHaveLength(1);
        const row = sessions[0];
        expect(row.type).toBe("DELEGATED_TOKEN");
        expect(row.userId).toBe(1);
        expect(row.permissions).toEqual(["play_sequence_override"]);
        expect(row.label).toBeNull();
        expect(row.refreshTokenHash).toBe(await sha256Hex(body.data.refreshToken));
        expect(body.data.tokenId).toBe(row.id);
        expect(row.parentId).toBeNull();

        // 90-day refresh token (same as a login), one-day JWT.
        const refreshTtl = row.expiresAt.getTime() - before;
        expect(refreshTtl).toBeGreaterThan(89 * 24 * 60 * 60 * 1000);
        expect(refreshTtl).toBeLessThanOrEqual(90 * 24 * 60 * 60 * 1000 + 1000);
        expect(body.data.expiresIn).toBe(86400);
        expect(new Date(body.data.refreshTokenExpiresAt).getTime()).toBe(
            row.expiresAt.getTime(),
        );
    });

    it("stores an optional label and returns it", async () => {
        const requestToken = await mintRequestToken({ scope: ["issue_tokens"] });
        const res = await issueToken(
            post({ scope: ["play_sequence_override"], label: "Music player" }, requestToken),
            {},
        );
        expect(res.status).toBe(200);
        expect((await res.json()).data.label).toBe("Music player");
        expect(sessions[0].label).toBe("Music player");
    });

    it("rejects minting when the GitHub session was revoked", async () => {
        const requestToken = await mintRequestToken({
            scope: ["issue_tokens"],
            sid: "revoked-session",
        });
        const res = await issueToken(
            post({ scope: ["play_sequence_override"] }, requestToken),
            {},
        );
        expect(res.status).toBe(401);
        expect((await res.json()).data.message).toContain("Session is no longer active");
    });

    it("caps live delegated tokens per user", async () => {
        for (let i = 0; i < 20; i++) {
            sessions.push({
                id: `seed-${i}`,
                userId: 1,
                type: "DELEGATED_TOKEN",
                refreshTokenHash: `hash-${i}`,
                previousRefreshTokenHash: null,
                permissions: ["play_sequence_override"],
                label: null,
                parentId: null,
                expiresAt: new Date(Date.now() + 86400000),
                createdAt: new Date(),
                updatedAt: new Date(),
            });
        }
        const requestToken = await mintRequestToken({ scope: ["issue_tokens"] });
        const res = await issueToken(
            post({ scope: ["play_sequence_override"] }, requestToken),
            {},
        );
        expect(res.status).toBe(429);
        expect((await res.json()).code).toBe(10004);
    });
});
