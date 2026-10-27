import { SessionType } from "@/generated/prisma/client";
import { request } from "@/test/request";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Codes } from "./codes";
import { ApiError } from "./response";
import {
    completeLoginSession,
    countActiveGithubSessions,
    findPendingLoginByState,
    generateRefreshToken,
    generateState,
    getClientIp,
    getUserAgent,
    inTx,
    MAX_GITHUB_SESSIONS,
    PENDING_LOGIN_TTL_MS,
    pruneExpiredSessions,
    REFRESH_TOKEN_TTL_MS,
    revokeSessionTree,
    sha256Hex,
    startLoginSession,
    type Db,
    type Tx,
} from "./sessions";

const { flags } = vi.hoisted(() => ({ flags: { tx: true } }));

vi.mock("./prisma", () => ({
    getPrisma: async () => ({}),
    supportsTransactions: () => flags.tx,
}));

interface Row {
    id: string;
    userId: number;
    type: string;
    state: string | null;
    expiresAt: Date;
}

function loginRow(id: string, expiresAt: Date, state: string | null = null): Row {
    return { id, userId: 1, type: SessionType.GITHUB_LOGIN, state, expiresAt };
}

/** Minimal scripted fake of the session delegate. */
function makeDb(active: number = 0, opts: { expired?: number } = {}) {
    const rows: Row[] = [];
    const now = Date.now();
    for (let i = 0; i < active; i++) {
        rows.push(loginRow(`active-${i}`, new Date(now + 60_000)));
    }
    for (let i = 0; i < (opts.expired ?? 0); i++) {
        rows.push(loginRow(`expired-${i}`, new Date(now - 60_000)));
    }
    const created: Array<Record<string, unknown>> = [];
    const updated: Array<Record<string, unknown>> = [];
    const calls: string[] = [];
    let seq = 0;
    const tx: Tx = {
        user: {
            update: vi.fn(async () => ({})),
        },
        session: {
            deleteMany: vi.fn(async ({ where }: { where: { expiresAt?: { lt: Date }; id?: string } }) => {
                calls.push("deleteMany");
                let count = 0;
                for (let i = rows.length - 1; i >= 0; i--) {
                    const matches = where.id
                        ? rows[i].id === where.id
                        : where.expiresAt
                            ? rows[i].expiresAt < where.expiresAt.lt
                            : false;
                    if (matches) {
                        rows.splice(i, 1);
                        count++;
                    }
                }
                return { count };
            }),
            count: vi.fn(
                async ({ where }: { where: { type: string; expiresAt: { gte: Date } } }) => {
                    calls.push("count");
                    return rows.filter(
                        (r) => r.type === where.type && r.expiresAt >= where.expiresAt.gte,
                    ).length;
                },
            ),
            findUnique: vi.fn(async ({ where }: { where: { state?: string } }) => {
                calls.push("findUnique");
                if (where.state === undefined) return null;
                return rows.find((r) => r.state === where.state) ?? null;
            }),
            create: vi.fn(async ({ data }: { data: Record<string, unknown> }) => {
                calls.push("create");
                const row = { id: `new-${seq++}`, ...data };
                created.push(row);
                rows.push(row as unknown as Row);
                return row;
            }),
            updateMany: vi.fn(
                async ({
                    where,
                    data,
                }: {
                    where: { id?: string; state?: string | null };
                    data: Record<string, unknown>;
                }) => {
                    calls.push("updateMany");
                    const row = rows.find(
                        (r) =>
                            (where.id === undefined || r.id === where.id) &&
                            (where.state === undefined || r.state === where.state),
                    );
                    if (!row) {
                        return { count: 0 };
                    }
                    Object.assign(row, data);
                    return { count: 1 };
                },
            ),
            update: vi.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
                calls.push("update");
                const row = rows.find((r) => r.id === where.id);
                if (row) {
                    Object.assign(row, data);
                }
                updated.push({ where, data });
                return row;
            }),
            delete: vi.fn(async () => ({})),
        },
    } as unknown as Tx;
    const db = {
        ...tx,
        $transaction: vi.fn(async <R,>(fn: (t: Tx) => Promise<R>) => fn(db)),
    } as unknown as Db & { $transaction: ReturnType<typeof vi.fn> };
    return { db, tx, created, updated, calls, rows };
}

beforeEach(() => {
    flags.tx = true;
});

describe("primitives", () => {
    it("hashes with SHA-256 (known vector)", async () => {
        await expect(sha256Hex("abc")).resolves.toBe(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );
    });

    it("generates base64url refresh tokens of 256 bits", () => {
        for (let i = 0; i < 20; i++) {
            expect(generateRefreshToken()).toMatch(/^[A-Za-z0-9_-]{43}$/);
        }
    });

    it("generates base64url OAuth states of 256 bits", () => {
        for (let i = 0; i < 20; i++) {
            expect(generateState()).toMatch(/^[A-Za-z0-9_-]{43}$/);
        }
    });
});

describe("inTx", () => {
    it("runs inside $transaction when the adapter supports it", async () => {
        const { db } = makeDb();
        await inTx(db, async () => "ok");
        expect(db.$transaction).toHaveBeenCalledTimes(1);
    });

    it("falls back to sequential statements on the HTTP transport", async () => {
        flags.tx = false;
        const { db } = makeDb();
        await inTx(db, async () => "ok");
        expect(db.$transaction).not.toHaveBeenCalled();
    });
});

describe("startLoginSession", () => {
    it("writes a pending GITHUB_LOGIN row carrying the state (short TTL)", async () => {
        const { db, created, calls } = makeDb(0);
        const { state } = await startLoginSession(db, { userId: 1 });
        expect(calls).toEqual(["deleteMany", "count", "create"]);
        expect(created).toHaveLength(1);
        const [pending] = created;
        expect(pending.type).toBe(SessionType.GITHUB_LOGIN);
        expect(pending.state).toBe(state);
        // Raw client info is never written to the session row.
        expect(pending).not.toHaveProperty("ip");
        expect(pending).not.toHaveProperty("userAgent");
        const ttl = (pending.expiresAt as Date).getTime() - Date.now();
        expect(ttl).toBeGreaterThan(PENDING_LOGIN_TTL_MS - 5000);
        expect(ttl).toBeLessThanOrEqual(PENDING_LOGIN_TTL_MS);
    });

    it(`rejects with 10004 when ${MAX_GITHUB_SESSIONS} sessions are already active`, async () => {
        const { db, created } = makeDb(MAX_GITHUB_SESSIONS);
        const promise = startLoginSession(db, { userId: 1 });
        await expect(promise).rejects.toBeInstanceOf(ApiError);
        await expect(promise).rejects.toMatchObject({ code: Codes.SESSION_LIMIT });
        expect(created).toHaveLength(0);
    });

    it("prunes expired sessions before counting, so they free up a slot", async () => {
        const { db, created, calls } = makeDb(MAX_GITHUB_SESSIONS - 1, { expired: 1 });
        await startLoginSession(db, { userId: 1 });
        expect(calls[0]).toBe("deleteMany");
        expect(created).toHaveLength(1);
    });

    it("runs the whole critical section in one $transaction", async () => {
        const { db } = makeDb(0);
        await startLoginSession(db, { userId: 1 });
        expect(db.$transaction).toHaveBeenCalledTimes(1);
    });
});

describe("findPendingLoginByState", () => {
    it("returns the pending session for a known state", async () => {
        const { db } = makeDb(0);
        const { state } = await startLoginSession(db, { userId: 1 });
        await expect(findPendingLoginByState(db, state)).resolves.toMatchObject({ userId: 1 });
    });

    it("rejects an unknown state with 10011", async () => {
        const { db } = makeDb(0);
        await expect(findPendingLoginByState(db, "missing")).rejects.toMatchObject({
            code: Codes.OAUTH_STATE_INVALID,
        });
    });

    it("rejects an expired pending state with 10011", async () => {
        const { db, rows } = makeDb(0);
        const { state } = await startLoginSession(db, { userId: 1 });
        rows.find((r) => r.state === state)!.expiresAt = new Date(Date.now() - 1000);
        await expect(findPendingLoginByState(db, state)).rejects.toMatchObject({
            code: Codes.OAUTH_STATE_INVALID,
        });
    });
});

describe("completeLoginSession", () => {
    it("attaches the REFRESH_TOKEN child, extends the login and consumes the state", async () => {
        const { db, created, updated, rows, calls } = makeDb(0);
        const { state, sessionId } = await startLoginSession(db, { userId: 1 });
        const result = await completeLoginSession(db, { state });
        expect(created).toHaveLength(2);
        const tokenRow = created[1];
        expect(tokenRow.type).toBe(SessionType.REFRESH_TOKEN);
        expect(tokenRow.parentId).toBe(sessionId);
        expect(tokenRow.refreshTokenHash).toBe(await sha256Hex(result.refreshToken));
        const ttl = (tokenRow.expiresAt as Date).getTime() - Date.now();
        expect(ttl).toBeGreaterThan(REFRESH_TOKEN_TTL_MS - 5000);
        // The login row is extended and its one-time state consumed.
        const login = rows.find((r) => r.id === sessionId)!;
        expect(login.expiresAt.getTime()).toBeGreaterThan(Date.now() + REFRESH_TOKEN_TTL_MS - 5000);
        expect(login.state).toBeNull();
        expect(calls).toContain("updateMany");
        expect(updated).toHaveLength(1);
    });

    it("rejects an unknown state with 10011", async () => {
        const { db, created } = makeDb(0);
        await expect(
            completeLoginSession(db, { state: "missing" }),
        ).rejects.toMatchObject({ code: Codes.OAUTH_STATE_INVALID });
        expect(created).toHaveLength(0);
    });

    it("deletes the refresh row when the login update fails (no-tx transport)", async () => {
        flags.tx = false;
        const { db, created } = makeDb(0);
        const { state } = await startLoginSession(db, { userId: 1 });
        vi.mocked(db.session.update).mockRejectedValueOnce(new Error("write failed"));
        await expect(completeLoginSession(db, { state })).rejects.toThrow("write failed");
        const child = created[1];
        // No transaction to roll back, so the orphaned (never-returned) child
        // must be deleted explicitly.
        expect(db.session.delete).toHaveBeenCalledWith({ where: { id: child.id } });
    });

    it("allows only one concurrent callback to consume the state", async () => {
        const { db, created } = makeDb(0);
        const { state } = await startLoginSession(db, { userId: 1 });
        const results = await Promise.allSettled([
            completeLoginSession(db, { state }),
            completeLoginSession(db, { state }),
        ]);
        expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
        expect(results.filter((r) => r.status === "rejected")).toHaveLength(1);
        expect(created.filter((r) => r.type === SessionType.REFRESH_TOKEN)).toHaveLength(1);
    });

    it("rejects a replayed (already consumed) state with 10011", async () => {
        const { db } = makeDb(0);
        const { state } = await startLoginSession(db, { userId: 1 });
        await completeLoginSession(db, { state });
        await expect(
            completeLoginSession(db, { state }),
        ).rejects.toMatchObject({ code: Codes.OAUTH_STATE_INVALID });
    });
});

describe("countActiveGithubSessions / pruneExpiredSessions", () => {
    it("counts only unexpired GITHUB_LOGIN rows", async () => {
        const { db } = makeDb(2, { expired: 1 });
        await expect(countActiveGithubSessions(db, 1)).resolves.toBe(2);
    });

    it("prune removes expired rows", async () => {
        const { db, rows } = makeDb(1, { expired: 2 });
        await expect(pruneExpiredSessions(db, 1)).resolves.toBe(2);
        expect(rows).toHaveLength(1);
    });
});

describe("revokeSessionTree", () => {
    it("deletes the parent when given a child so the cascade takes both", async () => {
        const { db } = makeDb();
        await revokeSessionTree(db, { id: "child", parentId: "parent" });
        expect(db.session.deleteMany).toHaveBeenCalledWith({ where: { id: "parent" } });
    });

    it("deletes the row itself when it has no parent", async () => {
        const { db } = makeDb();
        await revokeSessionTree(db, { id: "parent", parentId: null });
        expect(db.session.deleteMany).toHaveBeenCalledWith({ where: { id: "parent" } });
    });
});

describe("client info headers (Cloudflare ingress)", () => {
    function withHeaders(headers: Record<string, string>) {
        return request("http://localhost/", { headers });
    }

    it("prefers CF-Connecting-IP over forwarded headers", () => {
        const req = withHeaders({
            "cf-connecting-ip": "203.0.113.9",
            "x-forwarded-for": "10.0.0.1, 10.0.0.2",
            "x-real-ip": "10.0.0.3",
        });
        expect(getClientIp(req)).toBe("203.0.113.9");
    });

    it("trims CF-Connecting-IP and ignores a blank one", () => {
        expect(getClientIp(withHeaders({ "cf-connecting-ip": "  203.0.113.9  " }))).toBe(
            "203.0.113.9",
        );
        expect(
            getClientIp(
                withHeaders({ "cf-connecting-ip": "  ", "x-forwarded-for": " 10.0.0.1 , " }),
            ),
        ).toBe("10.0.0.1");
    });

    it("falls back to the first X-Forwarded-For entry", () => {
        expect(
            getClientIp(withHeaders({ "x-forwarded-for": "10.0.0.1, 10.0.0.2" })),
        ).toBe("10.0.0.1");
    });

    it("falls back to X-Real-IP, then unknown", () => {
        expect(getClientIp(withHeaders({ "x-real-ip": "10.0.0.3" }))).toBe("10.0.0.3");
        expect(getClientIp(withHeaders({}))).toBe("unknown");
        expect(getClientIp(withHeaders({ "x-real-ip": " " }))).toBe("unknown");
    });

    it("reads and trims the forwarded User-Agent", () => {
        expect(getUserAgent(withHeaders({ "user-agent": "  Firefox/120  " }))).toBe("Firefox/120");
    });

    it("returns unknown for a missing or blank User-Agent", () => {
        expect(getUserAgent(withHeaders({}))).toBe("unknown");
        expect(getUserAgent(withHeaders({ "user-agent": "   " }))).toBe("unknown");
    });
});
