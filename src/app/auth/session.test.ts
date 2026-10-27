import { exportJWK, generateKeyPair, importJWK, jwtVerify, SignJWT, type JWK } from "jose";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { hashActivity } from "@/lib/activity";
import { sha256Hex } from "@/lib/sessions";
import { request } from "@/test/request";
import { POST as refresh } from "./refresh/route";
import { POST as revoke } from "./revoke/route";
import { GET as listSessions } from "./sessions/route";

// In-memory stand-in for the Prisma client (users + sessions + jwks), with
// cascade deletes mirroring the schema's onDelete: Cascade.
const { fakeDb, sessions, keys, alice, bob, activityHashes } = vi.hoisted(() => {
    type UserRow = {
        id: number;
        name: string;
        email: string;
        githubId: string;
        permissions: string[];
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
    type JwkRow = {
        id: string;
        kid: string;
        publicKey: string;
        privateKey: string;
        createdAt: Date;
    };
    type ActivityHashRow = {
        id: string;
        userId: number;
        hash: string;
        createdAt: Date;
    };
    const alice: UserRow = {
        id: 1,
        name: "alice",
        email: "alice@example.com",
        githubId: "111",
        permissions: [],
    };
    const bob: UserRow = {
        id: 2,
        name: "bob",
        email: "bob@example.com",
        githubId: "222",
        permissions: [],
    };
    const users: UserRow[] = [alice, bob];
    const sessions: SessionRow[] = [];
    const keys: JwkRow[] = [];
    const activityHashes: ActivityHashRow[] = [];
    let seq = 0;

    function matches(row: SessionRow, where: Record<string, unknown>): boolean {
        for (const [key, cond] of Object.entries(where)) {
            if (key === "expiresAt") {
                const c = cond as { lt?: Date; gte?: Date };
                if (c.lt !== undefined && !(row.expiresAt < c.lt)) return false;
                if (c.gte !== undefined && !(row.expiresAt >= c.gte)) return false;
            } else if ((row as Record<string, unknown>)[key] !== cond) {
                return false;
            }
        }
        return true;
    }

    const user = {
        findFirst: async ({ where }: { where?: { name?: { equals?: string } } } = {}) => {
            const name = where?.name?.equals;
            if (name === undefined) return null;
            return users.find((u) => u.name.toLowerCase() === name.toLowerCase()) ?? null;
        },
        findMany: async ({ where }: { where?: { name?: { equals?: string } } } = {}) => {
            const name = where?.name?.equals;
            if (name === undefined) return [...users];
            return users.filter((u) => u.name.toLowerCase() === name.toLowerCase());
        },
        findUnique: async ({ where }: { where: { id?: number } }) => {
            if (where.id !== undefined) {
                return users.find((u) => u.id === where.id) ?? null;
            }
            return null;
        },
    };

    const session = {
        findMany: async (args: { where?: Record<string, unknown> } = {}) => {
            let rows = [...sessions];
            if (args.where) rows = rows.filter((r) => matches(r, args.where!));
            return rows.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
        },
        findUnique: async ({ where }: { where: Record<string, unknown> }) => {
            if (where.id !== undefined) {
                return sessions.find((r) => r.id === where.id) ?? null;
            }
            if (where.refreshTokenHash !== undefined) {
                return sessions.find((r) => r.refreshTokenHash === where.refreshTokenHash) ?? null;
            }
            return null;
        },
        findFirst: async ({ where }: { where: Record<string, unknown> }) => {
            const ors = (where.OR as Array<Record<string, unknown>>) ?? [];
            const userId = where.userId as number | undefined;
            if (where.id !== undefined) {
                return (
                    sessions.find(
                        (row) =>
                            row.id === where.id &&
                            (userId === undefined || row.userId === userId),
                    ) ?? null
                );
            }
            return (
                sessions.find((row) => {
                    if (userId !== undefined && row.userId !== userId) return false;
                    return ors.some((cond) =>
                        cond.refreshTokenHash !== undefined
                            ? row.refreshTokenHash === cond.refreshTokenHash
                            : row.previousRefreshTokenHash === cond.previousRefreshTokenHash,
                    );
                }) ?? null
            );
        },
        count: async ({ where }: { where: Record<string, unknown> }) =>
            sessions.filter((r) => matches(r, where)).length,
        create: async ({ data }: { data: Partial<SessionRow> }) => {
            const row: SessionRow = {
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
            sessions.push(row);
            return row;
        },
        updateMany: async ({
            where,
            data,
        }: {
            where: { id: string; refreshTokenHash: string };
            data: Partial<SessionRow>;
        }) => {
            let count = 0;
            for (const row of sessions) {
                if (row.id === where.id && row.refreshTokenHash === where.refreshTokenHash) {
                    Object.assign(row, data);
                    row.updatedAt = new Date();
                    count++;
                }
            }
            return { count };
        },
        update: async ({ where }: { where: { id: string } }) => {
            const row = sessions.find((r) => r.id === where.id);
            if (!row) throw Object.assign(new Error("not found"), { code: "P2025" });
            row.updatedAt = new Date();
            return row;
        },
        delete: async ({ where }: { where: { id: string } }) => {
            const idx = sessions.findIndex((r) => r.id === where.id);
            if (idx < 0) throw Object.assign(new Error("not found"), { code: "P2025" });
            const [row] = sessions.splice(idx, 1);
            for (let i = sessions.length - 1; i >= 0; i--) {
                if (sessions[i].parentId === row.id) sessions.splice(i, 1);
            }
            return row;
        },
        deleteMany: async ({ where }: { where: Record<string, unknown> }) => {
            if (typeof where.id === "string") {
                const idx = sessions.findIndex((r) => r.id === where.id);
                if (idx < 0) return { count: 0 };
                const [row] = sessions.splice(idx, 1);
                for (let i = sessions.length - 1; i >= 0; i--) {
                    if (sessions[i].parentId === row.id) sessions.splice(i, 1);
                }
                return { count: 1 };
            }
            let count = 0;
            for (let i = sessions.length - 1; i >= 0; i--) {
                if (matches(sessions[i], where)) {
                    sessions.splice(i, 1);
                    count++;
                }
            }
            return { count };
        },
    };

    const jwk = {
        findMany: async () => [...keys].sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime()),
        create: async ({ data }: { data: Omit<JwkRow, "id" | "createdAt"> }) => {
            const rec: JwkRow = { id: `k${++seq}`, createdAt: new Date(), ...data };
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
    };

    const activityHash = {
        findFirst: async ({
            where,
        }: {
            where: { userId: number; hash: string; createdAt: { gte: Date } };
        }) =>
            activityHashes.find(
                (row) =>
                    row.userId === where.userId &&
                    row.hash === where.hash &&
                    row.createdAt >= where.createdAt.gte,
            ) ?? null,
        create: async ({ data }: { data: { userId: number; hash: string } }) => {
            const row: ActivityHashRow = { id: `a${++seq}`, createdAt: new Date(), ...data };
            activityHashes.push(row);
            return row;
        },
        deleteMany: async ({ where }: { where: { createdAt: { lt: Date } } }) => {
            let count = 0;
            for (let i = activityHashes.length - 1; i >= 0; i--) {
                if (activityHashes[i].createdAt < where.createdAt.lt) {
                    activityHashes.splice(i, 1);
                    count++;
                }
            }
            return { count };
        },
    };

    const jwksLock = {
        createMany: async () => ({ count: 0 }),
        updateMany: async () => ({ count: 1 }),
    };
    const fakeDb = {
        user,
        session,
        jwk,
        jwksLock,
        activityHash,
        $transaction: vi.fn(async <T,>(fn: (tx: unknown) => Promise<T>): Promise<T> => fn(fakeDb)),
    };
    return { fakeDb, sessions, keys, alice, bob, activityHashes };
});

vi.mock("@/lib/prisma", () => ({
    getPrisma: async () => fakeDb,
    supportsTransactions: () => true,
}));

let privateJwk: JWK;
let fetchMock: ReturnType<typeof vi.fn>;
let consoleError: ReturnType<typeof vi.spyOn>;

beforeAll(async () => {
    const { publicKey, privateKey } = await generateKeyPair("RS256", {
        modulusLength: 4096,
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
    sessions.length = 0;
    activityHashes.length = 0;
    alice.permissions = [];
    bob.permissions = [];
    alice.email = "alice@example.com";
    bob.email = "bob@example.com";
    vi.stubEnv("RESEND_API_KEY", "re_test_key");
    vi.stubEnv("RESEND_FROM", "Api Bot <api-bot@noreply.jawbts.org>");
    vi.stubEnv("ACTIVITY_HASH_SALT", "test-salt");
    vi.stubEnv("JWKS_ENCRYPTION_KEY", "test-jwks-key");
    consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    fetchMock = vi.fn(
        async () =>
            new Response(JSON.stringify({ id: "email-1" }), {
                status: 200,
                headers: { "Content-Type": "application/json" },
            }),
    );
    vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
    consoleError.mockRestore();
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
});

async function apiJwt(sub: string, scope: string[] | undefined, ttlSeconds = 3600): Promise<string> {
    const key = await importJWK(privateJwk, "RS256");
    return new SignJWT(scope ? { scope } : {})
        .setProtectedHeader({ alg: "RS256", kid: String(privateJwk.kid) })
        .setIssuer("jawbts-api")
        .setSubject(sub)
        .setIssuedAt()
        .setExpirationTime(Math.floor(Date.now() / 1000) + ttlSeconds)
        .sign(key);
}

let seedSeq = 0;

async function seedSession(owner: { id: number; name: string }, opts: { ttlMs?: number } = {}) {
    const refreshToken = `rt-${crypto.randomUUID()}-${++seedSeq}`;
    const expiresAt = new Date(Date.now() + (opts.ttlMs ?? 90 * 24 * 60 * 60 * 1000));
    const login = {
        id: `login-${owner.name}-${seedSeq}`,
        userId: owner.id,
        type: "GITHUB_LOGIN",
        refreshTokenHash: null,
        previousRefreshTokenHash: null,
        permissions: [],
        label: null,
        parentId: null,
        expiresAt,
        createdAt: new Date(),
        updatedAt: new Date(),
    };
    const tokenRow = {
        id: `refresh-${owner.name}-${seedSeq}`,
        userId: owner.id,
        type: "REFRESH_TOKEN",
        refreshTokenHash: await sha256Hex(refreshToken),
        previousRefreshTokenHash: null,
        permissions: [],
        label: null,
        parentId: login.id,
        expiresAt,
        createdAt: new Date(),
        updatedAt: new Date(),
    };
    sessions.push(login, tokenRow);
    return { refreshToken, login, tokenRow };
}

async function seedDelegated(
    owner: { id: number; name: string },
    permissions: string[] = ["play_sequence_override"],
) {
    const refreshToken = `dt-${crypto.randomUUID()}-${++seedSeq}`;
    const expiresAt = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000);
    const delegated = {
        id: `delegated-${owner.name}-${seedSeq}`,
        userId: owner.id,
        type: "DELEGATED_TOKEN",
        refreshTokenHash: await sha256Hex(refreshToken),
        previousRefreshTokenHash: null,
        permissions: [...permissions],
        label: null,
        parentId: null,
        expiresAt,
        createdAt: new Date(),
        updatedAt: new Date(),
    };
    sessions.push(delegated);
    return { refreshToken, delegated };
}

function post(url: string, body: unknown, headers: Record<string, string> = {}) {
    return request(url, { method: "POST", body: JSON.stringify(body), headers });
}

describe("POST /auth/refresh", () => {
    it("rejects an unknown refresh token with 10002", async () => {
        const res = await refresh(
            post("http://localhost/auth/refresh", { refreshToken: "rt-unknown-token-12345" }),
            {},
        );
        expect(res.status).toBe(401);
        const body = await res.json();
        expect(body.code).toBe(10002);
    });

    it("rejects an expired refresh token with 10005 and revokes the pair", async () => {
        const seeded = await seedSession(alice, { ttlMs: -1000 });
        const res = await refresh(
            post("http://localhost/auth/refresh", { refreshToken: seeded.refreshToken }),
            {},
        );
        expect(res.status).toBe(401);
        expect((await res.json()).code).toBe(10005);
        expect(sessions).toHaveLength(0);
    });

    it("mints a scope-api JWT whose sub is the GitHub name", async () => {
        const seeded = await seedSession(alice);
        const res = await refresh(
            post(
                "http://localhost/auth/refresh",
                { refreshToken: seeded.refreshToken },
                {
                    "cf-connecting-ip": "203.0.113.9",
                    "x-forwarded-for": "10.0.0.1, 10.0.0.2",
                    "user-agent": "test-agent",
                },
            ),
            {},
        );
        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.data.scope).toEqual(["api"]);
        expect(body.data.expiresIn).toBe(600);

        const key = await importJWK(JSON.parse(keys[0].publicKey), "RS256");
        const { payload } = await jwtVerify(body.data.token, key);
        expect(payload.sub).toBe("alice");
        expect(payload.scope).toEqual(["api"]);
        expect((payload.exp as number) - (payload.iat as number)).toBe(600);
        expect(payload.sid).toBe(seeded.tokenRow.id);

        // Cloudflare's CF-Connecting-IP wins over the (spoofable) XFF entry:
        // the activity fingerprint is computed from it.
        expect(fakeDb.$transaction).toHaveBeenCalled();
        // Raw client info is never persisted on session rows.
        expect(seeded.tokenRow).not.toHaveProperty("ip");
        expect(seeded.tokenRow).not.toHaveProperty("userAgent");

        // The refresh token is rotated: a new opaque token is returned and
        // only its hash is stored, with the presented one kept for reuse
        // detection.
        const nextRefreshToken = body.data.refreshToken as string;
        expect(nextRefreshToken).toEqual(expect.stringMatching(/^[A-Za-z0-9_-]{40,}$/));
        expect(nextRefreshToken).not.toBe(seeded.refreshToken);
        expect(seeded.tokenRow.refreshTokenHash).toBe(await sha256Hex(nextRefreshToken));
        expect(seeded.tokenRow.previousRefreshTokenHash).toBe(
            await sha256Hex(seeded.refreshToken),
        );

        // New IP+UA fingerprint: one alert email and one stored hash.
        expect(fetchMock).toHaveBeenCalledTimes(1);
        expect(activityHashes).toHaveLength(1);
        expect(activityHashes[0].userId).toBe(alice.id);
        expect(activityHashes[0].hash).toBe(await hashActivity("203.0.113.9", "test-agent"));
    });

    it("puts only api and issue_tokens on the GitHub-issued scope", async () => {
        alice.permissions = ["issue_tokens", "play_sequence_override"];
        const seeded = await seedSession(alice);
        const res = await refresh(
            post("http://localhost/auth/refresh", { refreshToken: seeded.refreshToken }),
            {},
        );
        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.data.scope).toEqual(["api", "issue_tokens"]);

        const key = await importJWK(JSON.parse(keys[0].publicKey), "RS256");
        const { payload } = await jwtVerify(body.data.token, key);
        expect(payload.scope).toEqual(["api", "issue_tokens"]);
    });

    it("refreshes a delegated token with its stored scope and alerts", async () => {
        alice.permissions = ["issue_tokens", "play_sequence_override"];
        // A stale/non-delegable permission in the row must not survive.
        const seeded = await seedDelegated(alice, [
            "issue_tokens",
            "play_sequence_override",
            "legacy_permission",
        ]);
        const res = await refresh(
            post("http://localhost/auth/refresh", { refreshToken: seeded.refreshToken }),
            {},
        );
        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.data.scope).toEqual(["play_sequence_override"]);
        expect(body.data.expiresIn).toBe(86400);
        expect(body.data.refreshToken).toBeTruthy();
        expect(body.data.refreshToken).not.toBe(seeded.refreshToken);

        const key = await importJWK(JSON.parse(keys[0].publicKey), "RS256");
        const { payload } = await jwtVerify(body.data.token, key);
        expect(payload.scope).toEqual(["play_sequence_override"]);
        expect(payload.sid).toBe(seeded.delegated.id);

        // Every refresh alerts on a new fingerprint, delegated included.
        expect(fetchMock).toHaveBeenCalledTimes(1);
        expect(activityHashes).toHaveLength(1);
        expect(seeded.delegated.refreshTokenHash).toBe(await sha256Hex(body.data.refreshToken));
        expect(seeded.delegated.permissions).toEqual(["play_sequence_override"]);
    });

    it("revokes a delegated token once none of its permissions remain", async () => {
        alice.permissions = [];
        const seeded = await seedDelegated(alice);
        const res = await refresh(
            post("http://localhost/auth/refresh", { refreshToken: seeded.refreshToken }),
            {},
        );
        expect(res.status).toBe(401);
        expect((await res.json()).code).toBe(10006);
        expect(sessions).toHaveLength(0);
    });

    it("revokes a delegated token when its refresh token is replayed", async () => {
        alice.permissions = ["play_sequence_override"];
        const seeded = await seedDelegated(alice);
        const first = await refresh(
            post("http://localhost/auth/refresh", { refreshToken: seeded.refreshToken }),
            {},
        );
        expect(first.status).toBe(200);
        const replay = await refresh(
            post("http://localhost/auth/refresh", { refreshToken: seeded.refreshToken }),
            {},
        );
        expect(replay.status).toBe(401);
        expect((await replay.json()).code).toBe(10006);
        expect(sessions).toHaveLength(0);
    });

    it("rotates the refresh token and revokes the pair when it is replayed", async () => {
        const seeded = await seedSession(alice);
        const first = await refresh(
            post("http://localhost/auth/refresh", { refreshToken: seeded.refreshToken }),
            {},
        );
        expect(first.status).toBe(200);
        expect((await first.json()).data.refreshToken).toBeTruthy();

        const replay = await refresh(
            post("http://localhost/auth/refresh", { refreshToken: seeded.refreshToken }),
            {},
        );
        expect(replay.status).toBe(401);
        expect((await replay.json()).code).toBe(10006);
        expect(sessions).toHaveLength(0);
    });

    it("gets no second alert for the same fingerprint within 7 days", async () => {
        const seeded = await seedSession(alice);
        const headers = { "x-forwarded-for": "10.0.0.1", "user-agent": "test-agent" };
        const first = await refresh(
            post("http://localhost/auth/refresh", { refreshToken: seeded.refreshToken }, headers),
            {},
        );
        expect(first.status).toBe(200);
        const rotated = (await first.json()).data.refreshToken as string;
        const second = await refresh(
            post("http://localhost/auth/refresh", { refreshToken: rotated }, headers),
            {},
        );
        expect(second.status).toBe(200);
        expect(fetchMock).toHaveBeenCalledTimes(1);
        expect(activityHashes).toHaveLength(2);
    });

    it("fails with 10012 and does not spend the token when the alert email fails", async () => {
        const seeded = await seedSession(alice);
        fetchMock.mockResolvedValueOnce(new Response("nope", { status: 500 }));
        const res = await refresh(
            post("http://localhost/auth/refresh", { refreshToken: seeded.refreshToken }),
            {},
        );
        expect(res.status).toBe(502);
        const body = await res.json();
        expect(body.code).toBe(10012);
        expect(body.data.where).toBe("activity alert");
        expect(body.data.message).toBe("Email provider rejected the alert (HTTP 500)");
        expect(body.data.token).toBeUndefined();
        expect(activityHashes).toHaveLength(0);
        // The token was not rotated, so the client can retry the refresh.
        expect(seeded.tokenRow.refreshTokenHash).toBe(await sha256Hex(seeded.refreshToken));
        expect(seeded.tokenRow.previousRefreshTokenHash).toBeNull();
    });

    it("returns 400 for an invalid body", async () => {
        const res = await refresh(post("http://localhost/auth/refresh", {}), {});
        expect(res.status).toBe(400);
        expect((await res.json()).code).toBe(10001);
    });
});

describe("GET /auth/sessions", () => {
    it("requires a bearer token", async () => {
        const res = await listSessions(request("http://localhost/auth/sessions"), {});
        expect(res.status).toBe(401);
        expect((await res.json()).code).toBe(10002);
    });

    it("rejects a token without the api scope with 10007", async () => {
        const token = await apiJwt("alice", ["read"]);
        const res = await listSessions(
            request("http://localhost/auth/sessions", {
                headers: { authorization: `Bearer ${token}` },
            }),
            {},
        );
        expect(res.status).toBe(403);
        expect((await res.json()).code).toBe(10007);
    });

    it("rejects an expired JWT with 10005", async () => {
        const token = await apiJwt("alice", ["api"], -10);
        const res = await listSessions(
            request("http://localhost/auth/sessions", {
                headers: { authorization: `Bearer ${token}` },
            }),
            {},
        );
        expect(res.status).toBe(401);
        const body = await res.json();
        expect(body.code).toBe(10005);
        expect(body.data.where).toBe("claim \"exp\"");
    });

    it("returns 404 (10008) when the subject is not a user", async () => {
        const token = await apiJwt("ghost", ["api"]);
        const res = await listSessions(
            request("http://localhost/auth/sessions", {
                headers: { authorization: `Bearer ${token}` },
            }),
            {},
        );
        expect(res.status).toBe(404);
        expect((await res.json()).code).toBe(10008);
    });

    it("lists only the caller's live sessions and prunes expired ones", async () => {
        await seedSession(alice);
        await seedSession(alice, { ttlMs: -1000 });
        await seedSession(bob);
        await seedDelegated(alice);
        const token = await apiJwt("alice", ["api"]);
        const res = await listSessions(
            request("http://localhost/auth/sessions", {
                headers: { authorization: `Bearer ${token}` },
            }),
            {},
        );
        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.data.sessions).toHaveLength(3);
        expect(body.data.sessions.every((s: { id: string }) => s.id.includes("-alice-"))).toBe(true);
        // Client IP / user agent are never stored, so they are never returned.
        for (const session of body.data.sessions) {
            expect(session).not.toHaveProperty("ip");
            expect(session).not.toHaveProperty("userAgent");
        }
        // Delegated tokens are listed with the scope they were granted.
        const delegated = body.data.sessions.find(
            (s: { type: string }) => s.type === "DELEGATED_TOKEN",
        );
        expect(delegated).toMatchObject({ permissions: ["play_sequence_override"] });
        // The expired alice pair was pruned; alice's live pair + delegated row
        // and bob's pair remain.
        expect(sessions).toHaveLength(5);
        expect(sessions.every((s) => s.expiresAt > new Date())).toBe(true);
        expect(sessions.filter((s) => s.userId === bob.id)).toHaveLength(2);
    });
});

describe("POST /auth/revoke", () => {
    it("revokes a refresh-token session by id, removing the whole login pair", async () => {
        const seeded = await seedSession(alice);
        const token = await apiJwt("alice", ["api"]);
        const res = await revoke(
            post(
                "http://localhost/auth/revoke",
                { sessionId: seeded.login.id },
                { authorization: `Bearer ${token}` },
            ),
            {},
        );
        expect(res.status).toBe(200);
        expect((await res.json()).data.revoked).toBe(true);
        expect(sessions).toHaveLength(0);
    });

    it("revokes a delegated session by id without touching the login pair", async () => {
        await seedSession(alice);
        const delegated = await seedDelegated(alice);
        const token = await apiJwt("alice", ["api"]);
        const res = await revoke(
            post(
                "http://localhost/auth/revoke",
                { sessionId: delegated.delegated.id },
                { authorization: `Bearer ${token}` },
            ),
            {},
        );
        expect(res.status).toBe(200);
        expect(sessions.some((s) => s.id === delegated.delegated.id)).toBe(false);
        // The GitHub login pair is still there.
        expect(sessions).toHaveLength(2);
    });

    it("rejects the old refreshToken body shape", async () => {
        const seeded = await seedSession(alice);
        const token = await apiJwt("alice", ["api"]);
        const res = await revoke(
            post(
                "http://localhost/auth/revoke",
                { refreshToken: seeded.refreshToken },
                { authorization: `Bearer ${token}` },
            ),
            {},
        );
        expect(res.status).toBe(400);
        expect((await res.json()).code).toBe(10001);
        expect(sessions).toHaveLength(2);
    });

    it("cannot revoke another user's session by id", async () => {
        const seeded = await seedSession(bob);
        const token = await apiJwt("alice", ["api"]);
        const res = await revoke(
            post(
                "http://localhost/auth/revoke",
                { sessionId: seeded.login.id },
                { authorization: `Bearer ${token}` },
            ),
            {},
        );
        expect(res.status).toBe(404);
        expect((await res.json()).code).toBe(10000);
        expect(sessions).toHaveLength(2);
    });

    it("requires sessionId in the body", async () => {
        const token = await apiJwt("alice", ["api"]);
        const res = await revoke(
            post("http://localhost/auth/revoke", {}, { authorization: `Bearer ${token}` }),
            {},
        );
        expect(res.status).toBe(400);
        expect((await res.json()).code).toBe(10001);
    });
});

describe("pending email change", () => {
    it("records a fingerprint without alerting while the email is a placeholder", async () => {
        alice.email = "pending-1@placeholder.jawbts.org";
        const seeded = await seedSession(alice);
        const res = await refresh(
            post("http://localhost/auth/refresh", { refreshToken: seeded.refreshToken }),
            {},
        );
        expect(res.status).toBe(200);
        expect(fetchMock).not.toHaveBeenCalled();
        expect(activityHashes).toHaveLength(0);
    });
});
