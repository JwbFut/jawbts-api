import { exportJWK, generateKeyPair, importJWK, SignJWT, type JWK } from "jose";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { resetRemoteJwksForTests } from "@/lib/jwks-remote";
import { request } from "@/test/request";
import { POST as verifyToken } from "./verify/route";

const JWKS_URL = "http://localhost/.well-known/jwks.json";

interface TestKey {
    privateJwk: JWK;
    publicJwk: JWK;
}

let keyA: TestKey;
let keyB: TestKey;
let fetchMock: ReturnType<typeof vi.fn>;
let consoleError: ReturnType<typeof vi.spyOn>;

async function makeKey(): Promise<TestKey> {
    const { publicKey, privateKey } = await generateKeyPair("RS256", {
        modulusLength: 2048,
        extractable: true,
    });
    const publicJwk = await exportJWK(publicKey);
    const privateJwk = await exportJWK(privateKey);
    const kid = crypto.randomUUID();
    publicJwk.kid = kid;
    publicJwk.alg = "RS256";
    publicJwk.use = "sig";
    privateJwk.kid = kid;
    return { privateJwk, publicJwk };
}

beforeAll(async () => {
    keyA = await makeKey();
    keyB = await makeKey();
}, 30000);

function jwksResponse(keys: JWK[]): Response {
    return new Response(JSON.stringify({ keys }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
    });
}

beforeEach(() => {
    resetRemoteJwksForTests();
    consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    fetchMock = vi.fn(async () => jwksResponse([keyA.publicJwk]));
    vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
    vi.useRealTimers();
    consoleError.mockRestore();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
});

function post(body: unknown) {
    return request("http://localhost/auth/verify", {
        method: "POST",
        body: JSON.stringify(body),
    });
}

async function mintWith(
    key: TestKey,
    opts: { issuer?: string; expiresIn?: number; kid?: string } = {},
): Promise<string> {
    const jwk = await importJWK(key.privateJwk, "RS256");
    return new SignJWT({ scope: ["api"] })
        .setProtectedHeader({ alg: "RS256", kid: opts.kid ?? String(key.privateJwk.kid) })
        .setIssuer(opts.issuer ?? "jawbts-api")
        .setSubject("alice")
        .setIssuedAt()
        .setExpirationTime(Math.floor(Date.now() / 1000) + (opts.expiresIn ?? 3600))
        .sign(jwk);
}

const mint = (opts: { issuer?: string; expiresIn?: number } = {}) => mintWith(keyA, opts);

describe("POST /auth/verify (remote JWKS, cached by jose)", () => {
    it("verifies a token with the JWKS document served at /.well-known/jwks.json", async () => {
        const token = await mint();
        const res = await verifyToken(post({ token }), {});
        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.data.valid).toBe(true);
        expect(body.data.payload.sub).toBe("alice");
        expect(body.data.payload.iss).toBe("jawbts-api");

        expect(fetchMock).toHaveBeenCalledTimes(1);
        const [url] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
        expect(String(url)).toBe(JWKS_URL);
    });

    it("reuses the cached JWKS for subsequent verifications", async () => {
        const token = await mint();
        expect((await verifyToken(post({ token }), {})).status).toBe(200);
        expect((await verifyToken(post({ token }), {})).status).toBe(200);
        expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it("refetches once the 60s cache age is exceeded", async () => {
        const token = await mint();
        expect((await verifyToken(post({ token }), {})).status).toBe(200);
        vi.useFakeTimers();
        vi.advanceTimersByTime(61_000);
        expect((await verifyToken(post({ token }), {})).status).toBe(200);
        expect(fetchMock).toHaveBeenCalledTimes(2);
    });

    it("refetches when a rotated key (unknown kid) appears, after cooldown", async () => {
        const tokenA = await mint();
        expect((await verifyToken(post({ token: tokenA }), {})).status).toBe(200);
        expect(fetchMock).toHaveBeenCalledTimes(1);

        // The JWKS now also publishes key B; a token signed with B arrives
        // after the 5s cooldown has elapsed.
        fetchMock.mockResolvedValue(jwksResponse([keyA.publicJwk, keyB.publicJwk]));
        const tokenB = await mintWith(keyB);
        vi.useFakeTimers();
        vi.advanceTimersByTime(6_000);
        const res = await verifyToken(post({ token: tokenB }), {});
        expect(res.status).toBe(200);
        expect(fetchMock).toHaveBeenCalledTimes(2);
    });

    it("does not refetch for an unknown kid inside the cooldown window", async () => {
        expect((await verifyToken(post({ token: await mint() }), {})).status).toBe(200);
        const unknown = await mintWith(keyB);
        const res = await verifyToken(post({ token: unknown }), {});
        expect(res.status).toBe(401);
        expect((await res.json()).code).toBe(10006);
        // Only the initial JWKS load; a forged kid cannot amplify fetches.
        expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it("rejects a tampered token with 10006 (signature)", async () => {
        const token = await mint();
        const tampered = token.slice(0, -4) + "AAAA";
        const res = await verifyToken(post({ token: tampered }), {});
        expect(res.status).toBe(401);
        const body = await res.json();
        expect(body.code).toBe(10006);
        expect(body.data.where).toBe("signature");
    });

    it("rejects a token from another issuer", async () => {
        const token = await mint({ issuer: "someone-else" });
        const res = await verifyToken(post({ token }), {});
        expect(res.status).toBe(401);
        const body = await res.json();
        expect(body.code).toBe(10006);
        expect(body.data.where).toContain("iss");
    });

    it("rejects an expired token with 10005", async () => {
        const token = await mint({ expiresIn: -10 });
        const res = await verifyToken(post({ token }), {});
        expect(res.status).toBe(401);
        expect((await res.json()).code).toBe(10005);
    });

    it("returns 500/10500 when the JWKS endpoint is unreachable", async () => {
        fetchMock.mockRejectedValueOnce(new TypeError("fetch failed"));
        const token = await mint();
        const res = await verifyToken(post({ token }), {});
        expect(res.status).toBe(500);
        const body = await res.json();
        expect(body.code).toBe(10500);
        expect(body.data.message).toBe("JWKS is unavailable");
    });

    it("returns 500/10500 when the JWKS response is malformed", async () => {
        fetchMock.mockResolvedValueOnce(
            new Response(JSON.stringify({ nope: true }), { status: 200 }),
        );
        const token = await mint();
        const res = await verifyToken(post({ token }), {});
        expect(res.status).toBe(500);
        expect((await res.json()).code).toBe(10500);
    });

    it("rejects a token whose header algorithm is not RS256", async () => {
        const token = await new SignJWT({})
            .setProtectedHeader({ alg: "HS256" })
            .setIssuer("jawbts-api")
            .setSubject("alice")
            .setIssuedAt()
            .setExpirationTime(Math.floor(Date.now() / 1000) + 3600)
            .sign(new TextEncoder().encode("symmetric-secret"));
        const res = await verifyToken(post({ token }), {});
        expect(res.status).toBe(401);
        const body = await res.json();
        expect(body.code).toBe(10006);
        expect(body.data.where).toBe("alg");
    });

    it("caps the token at 4096 characters and does not fetch the JWKS", async () => {
        const res = await verifyToken(post({ token: "x".repeat(4097) }), {});
        expect(res.status).toBe(400);
        expect((await res.json()).code).toBe(10001);
        expect(fetchMock).not.toHaveBeenCalled();
    });
});
