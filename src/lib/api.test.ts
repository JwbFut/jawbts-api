import { z } from "zod";
import { describe, expect, it, vi } from "vitest";
import { request } from "@/test/request";
import { Codes } from "./codes";
import { ApiError } from "./response";
import { api, isDbError, parseBody, parseParams } from "./api";

describe("parseBody", () => {
    const schema = z.object({ email: z.email() });

    it("parses a valid JSON body", async () => {
        const req = request("http://localhost/x", {
            method: "POST",
            body: JSON.stringify({ email: "a@b.com" }),
        });
        expect(await parseBody(req, schema)).toEqual({ email: "a@b.com" });
    });

    it("throws an ApiError on an empty body", async () => {
        const req = request("http://localhost/x", { method: "POST" });
        await expect(parseBody(req, schema)).rejects.toThrow(ApiError);
    });

    it("throws an ApiError on invalid JSON", async () => {
        const req = request("http://localhost/x", { method: "POST", body: "{oops" });
        await expect(parseBody(req, schema)).rejects.toThrow(ApiError);
    });

    it("rejects an oversized body with 400 instead of buffering it", async () => {
        const body = JSON.stringify({ email: "a@b.com", pad: "x".repeat(70_000) });
        const req = request("http://localhost/x", { method: "POST", body });
        const error = await parseBody(req, schema).catch((e: unknown) => e);
        expect(error).toBeInstanceOf(ApiError);
        expect((error as ApiError).code).toBe(Codes.BAD_REQUEST);
    });

    it("throws a ZodError on schema mismatch", async () => {
        const req = request("http://localhost/x", {
            method: "POST",
            body: JSON.stringify({ email: "not-an-email" }),
        });
        await expect(parseBody(req, schema)).rejects.toThrow(z.ZodError);
    });
});

describe("parseParams", () => {
    it("parses route params from ctx", async () => {
        const ctx = { params: Promise.resolve({ id: "abc" }) };
        const schema = z.object({ id: z.string().min(1) });
        expect(await parseParams(ctx, schema)).toEqual({ id: "abc" });
    });

    it("throws a ZodError on invalid params", async () => {
        const ctx = { params: Promise.resolve({ id: "" }) };
        const schema = z.object({ id: z.string().min(1) });
        await expect(parseParams(ctx, schema)).rejects.toThrow(z.ZodError);
    });
});

describe("isDbError", () => {
    function coded(code: string): Error {
        return Object.assign(new Error("db"), { code });
    }

    it("matches the Prisma code", () => {
        expect(isDbError(coded("P2002"), "P2002", "23505")).toBe(true);
    });

    it("matches the SQLSTATE", () => {
        expect(isDbError(coded("23505"), "P2002", "23505")).toBe(true);
    });

    it("matches a lone Prisma code without a SQLSTATE", () => {
        expect(isDbError(coded("P2025"), "P2025")).toBe(true);
    });

    it("returns false for a non-matching code", () => {
        expect(isDbError(coded("P2025"), "P2002", "23505")).toBe(false);
    });

    it("returns false for non-errors or errors without a code", () => {
        expect(isDbError(new Error("x"), "P2002")).toBe(false);
        expect(isDbError("nope", "P2002")).toBe(false);
        expect(isDbError(null, "P2002")).toBe(false);
        expect(isDbError(undefined, "P2002")).toBe(false);
    });
});

describe("api wrapper", () => {
    const req = request("http://localhost/x");

    it("returns the handler response unchanged", async () => {
        const handler = api(async () => Response.json({ ok: 1 }));
        const res = await handler(req, {});
        expect(res.status).toBe(200);
        expect(await res.json()).toEqual({ ok: 1 });
    });

    it("converts an ApiError into the fail envelope", async () => {
        const handler = api(async () => {
            throw new ApiError(Codes.NOT_FOUND);
        });
        const res = await handler(req, {});
        expect(res.status).toBe(404);
        expect((await res.json()).code).toBe(10000);
    });

    it("converts a ZodError into a 10001 envelope with issues", async () => {
        const handler = api(async () => {
            z.object({ email: z.email() }).parse({ email: "nope" });
            return Response.json({});
        });
        const res = await handler(req, {});
        expect(res.status).toBe(400);
        const body = await res.json();
        expect(body.code).toBe(10001);
        expect(body.data.issues).toBeDefined();
    });

    it("converts an unknown error into a 10500 envelope", async () => {
        const spy = vi.spyOn(console, "error").mockImplementation(() => {});
        const handler = api(async () => {
            throw new Error("boom");
        });
        const res = await handler(req, {});
        expect(res.status).toBe(500);
        expect((await res.json()).code).toBe(10500);
        spy.mockRestore();
    });
});

