import {
    JOSEAlgNotAllowed,
    JWSInvalid,
    JWSSignatureVerificationFailed,
} from "jose/errors";
import { exportJWK, generateKeyPair, importJWK, SignJWT, type JWK } from "jose";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { Codes } from "./codes";
import { joseFailure, requireScope } from "./jwt-guard";
import { request } from "@/test/request";

const { fakeDb, keys } = vi.hoisted(() => {
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
    const fakeDb = { jwk, jwksLock };
    return { fakeDb, keys };
});

vi.mock("./prisma", () => ({
    getPrisma: async () => fakeDb,
    supportsTransactions: () => true,
}));

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

async function jwt(opts: {
    scope?: string[];
    ttlSeconds?: number;
    issuer?: string;
    kid?: string;
}): Promise<string> {
    const key = await importJWK(privateJwk, "RS256");
    return new SignJWT(opts.scope ? { scope: opts.scope } : {})
        .setProtectedHeader({ alg: "RS256", kid: opts.kid ?? String(privateJwk.kid) })
        .setIssuer(opts.issuer ?? "jawbts-api")
        .setSubject("u1")
        .setIssuedAt()
        .setExpirationTime(Math.floor(Date.now() / 1000) + (opts.ttlSeconds ?? 3600))
        .sign(key);
}

function withToken(token: string | undefined) {
    return request("http://localhost/auth/sessions", {
        headers: token === undefined ? {} : { authorization: `Bearer ${token}` },
    });
}

describe("joseFailure mapping", () => {
    it("maps each jose error class to where it happened", () => {
        expect(joseFailure(new JWSSignatureVerificationFailed()).code).toBe(Codes.TOKEN_INVALID);
        expect(joseFailure(new JWSSignatureVerificationFailed()).where).toBe("signature");
        expect(joseFailure(new JOSEAlgNotAllowed()).where).toBe("alg");
        expect(joseFailure(new JWSInvalid("bad")).where).toBe("token format");
        expect(joseFailure(new Error("anything else")).where).toBe("verification");
        expect(joseFailure("not even an error").code).toBe(Codes.TOKEN_INVALID);
    });
});

describe("requireScope", () => {
    it("rejects a missing Authorization header with 10002", async () => {
        await expect(requireScope(withToken(undefined), "api")).rejects.toMatchObject({
            code: Codes.UNAUTHORIZED,
        });
    });

    it("rejects a malformed token with 10006 (token format)", async () => {
        await expect(requireScope(withToken("not-a-jwt"), "api")).rejects.toMatchObject({
            code: Codes.TOKEN_INVALID,
            data: { where: "token format" },
        });
    });

    it("rejects a token with an unknown kid with 10006 (kid)", async () => {
        const token = await jwt({ kid: crypto.randomUUID(), scope: ["api"] });
        await expect(requireScope(withToken(token), "api")).rejects.toMatchObject({
            code: Codes.TOKEN_INVALID,
            data: { where: "kid" },
        });
    });

    it("rejects an expired token with 10005", async () => {
        const token = await jwt({ scope: ["api"], ttlSeconds: -10 });
        await expect(requireScope(withToken(token), "api")).rejects.toMatchObject({
            code: Codes.TOKEN_EXPIRED,
            data: { where: "claim \"exp\"" },
        });
    });

    it("rejects a wrong issuer with 10006 (iss claim)", async () => {
        const token = await jwt({ scope: ["api"], issuer: "someone-else" });
        await expect(requireScope(withToken(token), "api")).rejects.toMatchObject({
            code: Codes.TOKEN_INVALID,
            data: { where: "claim \"iss\" (check_failed)" },
        });
    });

    it("rejects a valid token whose scope list lacks the required scope with 10007", async () => {
        const token = await jwt({ scope: ["read"] });
        await expect(requireScope(withToken(token), "api")).rejects.toMatchObject({
            code: Codes.INSUFFICIENT_SCOPE,
        });
    });

    it("rejects a valid token without any scope claim with 10007", async () => {
        const token = await jwt({});
        await expect(requireScope(withToken(token), "api")).rejects.toMatchObject({
            code: Codes.INSUFFICIENT_SCOPE,
        });
    });

    it("returns the payload for a valid token with the required scope", async () => {
        const token = await jwt({ scope: ["api", "read"] });
        const payload = await requireScope(withToken(token), "api");
        expect(payload.sub).toBe("u1");
        expect(payload.scope).toEqual(["api", "read"]);
    });
});
