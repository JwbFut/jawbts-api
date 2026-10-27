import { exportJWK, generateKeyPair, importJWK, SignJWT, type JWK } from "jose";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
    decodeEmailChangePlaceholder,
    encodeEmailChangePlaceholder,
    hashEmailChangeToken,
    isPlaceholderEmail,
} from "@/lib/email-change";
import { request, type NextRequestInit } from "@/test/request";
import { GET, PATCH } from "./route";

const { fakeDb, userMock, keys } = vi.hoisted(() => {
    const userMock = {
        findMany: vi.fn(),
        findFirst: vi.fn(),
        update: vi.fn(),
        updateMany: vi.fn(),
    };
    const keys: Array<{
        id: string;
        kid: string;
        publicKey: string;
        privateKey: string;
        createdAt: Date;
    }> = [];
    const jwk = {
        findMany: async () =>
            [...keys].sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime()),
        create: async ({ data }: { data: Omit<(typeof keys)[number], "id" | "createdAt"> }) => {
            const rec = { id: `k${keys.length + 1}`, createdAt: new Date(), ...data };
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
    const jwksLock = {
        createMany: async () => ({ count: 0 }),
        updateMany: async () => ({ count: 1 }),
    };
    const fakeDb = { user: userMock, jwk, jwksLock };
    return { fakeDb, userMock, keys };
});

vi.mock("@/lib/prisma", () => ({
    getPrisma: async () => fakeDb,
    supportsTransactions: () => true,
}));

interface FakeUser {
    id: number;
    email: string;
    name: string;
    githubId: string;
    permissions: string[];
    emailChangeTokenHash: string | null;
    emailChangeExpiresAt: Date | null;
    emailChangeLastSentAt: Date | null;
    createdAt: Date;
    updatedAt: Date;
}

function makeUser(overrides: Partial<FakeUser> = {}): FakeUser {
    const now = new Date("2026-08-03T12:00:00Z");
    return {
        id: 1,
        email: "a@b.com",
        name: "octocat",
        githubId: "583231",
        permissions: [],
        emailChangeTokenHash: null,
        emailChangeExpiresAt: null,
        emailChangeLastSentAt: null,
        createdAt: now,
        updatedAt: now,
        ...overrides,
    };
}

let privateJwk: JWK;

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
        createdAt: new Date(),
    });
    privateJwk = priv;
}, 30000);

let fetchMock: ReturnType<typeof vi.fn>;
let consoleError: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
    vi.clearAllMocks();
    userMock.findFirst.mockResolvedValue(null);
    userMock.findMany.mockResolvedValue([]);
    userMock.update.mockImplementation(
        async ({ data }: { data: Partial<FakeUser> }) => ({ ...makeUser(), ...data }),
    );
    userMock.updateMany.mockResolvedValue({ count: 1 });
    vi.stubEnv("RESEND_API_KEY", "re_test_key");
    vi.stubEnv("RESEND_FROM", "Api Bot <api-bot@noreply.jawbts.org>");
    fetchMock = vi.fn(
        async () =>
            new Response(JSON.stringify({ id: "email-1" }), {
                status: 200,
                headers: { "Content-Type": "application/json" },
            }),
    );
    vi.stubGlobal("fetch", fetchMock);
    consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
    consoleError.mockRestore();
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
});

async function apiJwt(sub: string, scope: string[] | undefined): Promise<string> {
    const key = await importJWK(privateJwk, "RS256");
    return new SignJWT(scope ? { scope } : {})
        .setProtectedHeader({ alg: "RS256", kid: String(privateJwk.kid) })
        .setIssuer("jawbts-api")
        .setSubject(sub)
        .setIssuedAt()
        .setExpirationTime(Math.floor(Date.now() / 1000) + 3600)
        .sign(key);
}

function withToken(token: string | undefined, init: NextRequestInit = {}) {
    return request("http://localhost/user", {
        ...init,
        headers: token === undefined ? {} : { authorization: `Bearer ${token}` },
    });
}

const NAME_QUERY = { where: { name: { equals: "octocat", mode: "insensitive" } }, take: 2 };

function sentEmails() {
    return fetchMock.mock.calls.map((call) =>
        JSON.parse(String((call as unknown as [string, RequestInit])[1].body)),
    ) as Array<{ to: string[]; subject: string; text: string }>;
}

function placeholder(from = "a@b.com", to = "new@b.com", expiresAt = new Date(Date.now() + 60_000)) {
    return encodeEmailChangePlaceholder({ from, to, expiresAt });
}

describe("GET /user", () => {
    it("requires a bearer token", async () => {
        const res = await GET(withToken(undefined), {});
        expect(res.status).toBe(401);
        expect((await res.json()).code).toBe(10002);
    });

    it("rejects a token without the api scope", async () => {
        const token = await apiJwt("octocat", ["read"]);
        const res = await GET(withToken(token), {});
        expect(res.status).toBe(403);
        expect((await res.json()).code).toBe(10007);
    });

    it("returns the caller's own profile and a real email", async () => {
        userMock.findMany.mockResolvedValue([makeUser()]);
        const token = await apiJwt("octocat", ["api"]);
        const res = await GET(withToken(token), {});
        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.data).toMatchObject({
            id: 1,
            email: "a@b.com",
            name: "octocat",
            githubId: "583231",
            permissions: [],
        });
        expect(body.data).not.toHaveProperty("emailChangeTokenHash");
        expect(userMock.findMany).toHaveBeenCalledWith(NAME_QUERY);
    });

    it("hides the email only while it is the placeholder", async () => {
        userMock.findMany.mockResolvedValue([
            makeUser({
                email: placeholder(),
                emailChangeTokenHash: "hash",
                emailChangeExpiresAt: new Date(Date.now() + 60_000),
            }),
        ]);
        const token = await apiJwt("octocat", ["api"]);
        const res = await GET(withToken(token), {});
        expect(res.status).toBe(200);
        expect((await res.json()).data).not.toHaveProperty("email");
    });

    it("shows a real email even if stale change metadata remains", async () => {
        userMock.findMany.mockResolvedValue([
            makeUser({
                email: "a@b.com",
                emailChangeTokenHash: "stale",
                emailChangeExpiresAt: new Date(Date.now() - 60_000),
            }),
        ]);
        const token = await apiJwt("octocat", ["api"]);
        const res = await GET(withToken(token), {});
        expect(res.status).toBe(200);
        expect((await res.json()).data.email).toBe("a@b.com");
    });

    it("does not restore an expired placeholder", async () => {
        userMock.findMany.mockResolvedValue([
            makeUser({
                email: placeholder("a@b.com", "new@b.com", new Date(Date.now() - 60_000)),
                emailChangeTokenHash: "hash",
                emailChangeExpiresAt: new Date(Date.now() - 60_000),
            }),
        ]);
        const token = await apiJwt("octocat", ["api"]);
        const res = await GET(withToken(token), {});
        expect(res.status).toBe(200);
        expect((await res.json()).data).not.toHaveProperty("email");
        expect(userMock.updateMany).not.toHaveBeenCalled();
        expect(userMock.updateMany).not.toHaveBeenCalled();
    });

    it("fails closed when the name matches more than one account", async () => {
        userMock.findMany.mockResolvedValue([
            { id: 1, name: "octocat" },
            { id: 2, name: "Octocat" },
        ]);
        const token = await apiJwt("octocat", ["api"]);
        const res = await GET(withToken(token), {});
        expect(res.status).toBe(403);
        expect((await res.json()).code).toBe(10010);
    });

    it("returns 404 (10008) when the subject is not a user", async () => {
        userMock.findMany.mockResolvedValue([]);
        const token = await apiJwt("ghost", ["api"]);
        const res = await GET(withToken(token), {});
        expect(res.status).toBe(404);
        expect((await res.json()).code).toBe(10008);
    });
});

describe("PATCH /user", () => {
    function patch(body: unknown, token: string) {
        return withToken(token, { method: "PATCH", body: JSON.stringify(body) });
    }

    it("encodes from/to/expiry into the placeholder and notifies both", async () => {
        userMock.findMany.mockResolvedValue([makeUser()]);
        const token = await apiJwt("octocat", ["api"]);
        const res = await PATCH(patch({ email: "new@b.com" }, token), {});
        expect(res.status).toBe(200);
        expect((await res.json()).data).not.toHaveProperty("email");

        const update = userMock.updateMany.mock.calls[0][0] as {
            data: Record<string, unknown>;
        };
        const encoded = update.data.email as string;
        expect(isPlaceholderEmail(encoded)).toBe(true);
        expect(decodeEmailChangePlaceholder(encoded)).toMatchObject({
            from: "a@b.com",
            to: "new@b.com",
        });
        expect(update.data.emailChangeExpiresAt).toBeInstanceOf(Date);
        expect(update.data.emailChangeLastSentAt).toBeInstanceOf(Date);

        const sent = sentEmails();
        expect(sent).toHaveLength(2);
        expect(sent[0].to).toEqual(["a@b.com"]);
        expect(sent[0].subject).toBe("Your jawbts email address is going to change");
        expect(sent[0].text).toContain("no deliverable email");
        expect(sent[0].text).not.toContain("continue to go to the previous address");
        expect(sent[1].to).toEqual(["new@b.com"]);
        expect(sent[1].subject).toBe("Confirm your new jawbts email address");
        const match = /Confirmation token: (\S+)/.exec(sent[1].text);
        expect(match).not.toBeNull();
        expect(update.data.emailChangeTokenHash).toBe(
            await hashEmailChangeToken(match![1]),
        );
    });

    it("sends nothing when the email is unchanged (case-insensitive)", async () => {
        userMock.findMany.mockResolvedValue([makeUser()]);
        const token = await apiJwt("octocat", ["api"]);
        const res = await PATCH(patch({ email: "A@B.com" }, token), {});
        expect(res.status).toBe(200);
        expect(fetchMock).not.toHaveBeenCalled();
        expect(userMock.updateMany).not.toHaveBeenCalled();
        expect((await res.json()).data.email).toBe("a@b.com");
    });

    it("rejects an over-long email before it can overflow the placeholder", async () => {
        const token = await apiJwt("octocat", ["api"]);
        const res = await PATCH(
            patch({ email: `${"a".repeat(300)}@b.com` }, token),
            {},
        );
        expect(res.status).toBe(400);
        expect((await res.json()).code).toBe(10001);
        expect(userMock.updateMany).not.toHaveBeenCalled();
    });

    it("returns an actionable error for a legacy/corrupt placeholder", async () => {
        userMock.findMany.mockResolvedValue([
            makeUser({
                email: "pending-1@placeholder.jawbts.org",
                emailChangeTokenHash: "legacy-hash",
                emailChangeExpiresAt: new Date(Date.now() + 60_000),
            }),
        ]);
        const token = await apiJwt("octocat", ["api"]);
        const res = await PATCH(patch({ email: "new@b.com" }, token), {});
        expect(res.status).toBe(409);
        expect((await res.json()).code).toBe(10015);
        expect(userMock.updateMany).not.toHaveBeenCalled();
        expect(fetchMock).not.toHaveBeenCalled();
    });

    it("rejects the reserved placeholder domain", async () => {
        const token = await apiJwt("octocat", ["api"]);
        const res = await PATCH(
            patch({ email: "attacker@placeholder.jawbts.org" }, token),
            {},
        );
        expect(res.status).toBe(400);
        expect((await res.json()).code).toBe(10001);
    });

    it("enforces the per-user cooldown", async () => {
        userMock.findMany.mockResolvedValue([
            makeUser({ emailChangeLastSentAt: new Date() }),
        ]);
        const token = await apiJwt("octocat", ["api"]);
        const res = await PATCH(patch({ email: "new@b.com" }, token), {});
        expect(res.status).toBe(429);
        expect((await res.json()).code).toBe(10014);
        expect(userMock.updateMany).not.toHaveBeenCalled();
        expect(fetchMock).not.toHaveBeenCalled();
    });

    it("rejects a case-insensitive clash with an active address", async () => {
        userMock.findMany.mockResolvedValue([makeUser()]);
        userMock.findFirst.mockResolvedValue({ id: 2, email: "Taken@b.com" });
        const token = await apiJwt("octocat", ["api"]);
        const res = await PATCH(patch({ email: "taken@b.com" }, token), {});
        expect(res.status).toBe(400);
        expect((await res.json()).data.message).toBe("Email already exists");
        expect(userMock.updateMany).not.toHaveBeenCalled();
        expect(fetchMock).not.toHaveBeenCalled();
    });

    it("rolls back to the old email when the old-address notice fails", async () => {
        userMock.findMany.mockResolvedValue([makeUser()]);
        fetchMock.mockResolvedValueOnce(new Response("down", { status: 500 }));
        const token = await apiJwt("octocat", ["api"]);
        const res = await PATCH(patch({ email: "new@b.com" }, token), {});
        expect(res.status).toBe(502);
        const body = await res.json();
        expect(body.code).toBe(10013);
        expect(fetchMock).toHaveBeenCalledTimes(1);
        expect(userMock.updateMany).toHaveBeenCalledTimes(2);
        const rollback = userMock.updateMany.mock.calls[1][0] as {
            data: Record<string, unknown>;
        };
        expect(rollback.data.email).toBe("a@b.com");
        expect(rollback.data.emailChangeTokenHash).toBeNull();
    });

    it("rolls back and cancels when the new-address notice fails", async () => {
        userMock.findMany.mockResolvedValue([makeUser()]);
        fetchMock
            .mockResolvedValueOnce(new Response("{}", { status: 200 }))
            .mockResolvedValueOnce(new Response("down", { status: 500 }))
            .mockResolvedValueOnce(new Response("{}", { status: 200 }));
        const token = await apiJwt("octocat", ["api"]);
        const res = await PATCH(patch({ email: "new@b.com" }, token), {});
        expect(res.status).toBe(502);
        expect((await res.json()).code).toBe(10013);
        expect(fetchMock).toHaveBeenCalledTimes(3);
        expect(sentEmails()[2].to).toEqual(["a@b.com"]);
        expect(sentEmails()[2].subject).toBe("Your jawbts email change was cancelled");
        expect(userMock.updateMany).toHaveBeenCalledTimes(2);
    });

    it("re-requests from an expired placeholder by decoding the old address", async () => {
        userMock.findMany.mockResolvedValue([
            makeUser({
                email: placeholder("a@b.com", "old-new@b.com", new Date(Date.now() - 60_000)),
                emailChangeTokenHash: "old-hash",
                emailChangeExpiresAt: new Date(Date.now() - 60_000),
                emailChangeLastSentAt: new Date(Date.now() - 120_000),
            }),
        ]);
        const token = await apiJwt("octocat", ["api"]);
        const res = await PATCH(patch({ email: "new@b.com" }, token), {});
        expect(res.status).toBe(200);
        const update = userMock.updateMany.mock.calls[0][0] as {
            data: Record<string, unknown>;
        };
        expect(decodeEmailChangePlaceholder(update.data.email as string)).toMatchObject({
            from: "a@b.com",
            to: "new@b.com",
        });
        expect(sentEmails()[0].to).toEqual(["a@b.com"]);
    });

    it("rejects any field other than email", async () => {
        const token = await apiJwt("octocat", ["api"]);
        const res = await PATCH(patch({ name: "Bobby" }, token), {});
        expect(res.status).toBe(400);
        expect((await res.json()).code).toBe(10001);
        expect(userMock.updateMany).not.toHaveBeenCalled();
    });

    it("maps unique-constraint violations on staging to 400", async () => {
        userMock.findMany.mockResolvedValue([makeUser()]);
        userMock.updateMany.mockRejectedValue(Object.assign(new Error("dup"), { code: "23505" }));
        const token = await apiJwt("octocat", ["api"]);
        const res = await PATCH(patch({ email: "taken@b.com" }, token), {});
        expect(res.status).toBe(400);
        expect((await res.json()).data.message).toBe("Email already exists");
    });

    it("rejects when a concurrent change wins before staging", async () => {
        userMock.findMany.mockResolvedValue([makeUser()]);
        userMock.updateMany.mockResolvedValue({ count: 0 });
        const token = await apiJwt("octocat", ["api"]);
        const res = await PATCH(patch({ email: "new@b.com" }, token), {});
        expect(res.status).toBe(409);
        expect((await res.json()).code).toBe(10015);
        expect(fetchMock).not.toHaveBeenCalled();
    });
});
