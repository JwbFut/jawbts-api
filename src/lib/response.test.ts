import { describe, expect, it } from "vitest";
import { Codes } from "./codes";
import { ApiError, fail, ok } from "./response";

describe("response envelope", () => {
    it("ok() returns a success envelope with HTTP 200", async () => {
        const res = ok({ a: 1 });
        expect(res.status).toBe(200);
        expect(await res.json()).toEqual({
            success: true,
            code: 200,
            message: "OK",
            data: { a: 1 },
        });
    });

    it("fail() returns an error envelope with the mapped status and null data by default", async () => {
        const res = fail(Codes.NOT_FOUND);
        expect(res.status).toBe(404);
        expect(await res.json()).toEqual({
            success: false,
            code: 10000,
            message: "Not Found",
            data: null,
        });
    });

    it("fail() carries the provided data", async () => {
        const res = fail(Codes.BAD_REQUEST, { issues: { email: ["Invalid email"] } });
        expect(res.status).toBe(400);
        const body = await res.json();
        expect(body.success).toBe(false);
        expect(body.code).toBe(10001);
        expect(body.data).toEqual({ issues: { email: ["Invalid email"] } });
    });

    it("always sets the Content-Type to JSON", () => {
        expect(ok(null).headers.get("content-type")).toContain("application/json");
        expect(fail(Codes.NOT_FOUND).headers.get("content-type")).toContain("application/json");
    });
});

describe("ApiError", () => {
    it("exposes code, data and the code message", () => {
        const err = new ApiError(Codes.FORBIDDEN, { reason: "x" });
        expect(err.code).toBe(10003);
        expect(err.data).toEqual({ reason: "x" });
        expect(err.message).toBe("Forbidden");
        expect(err).toBeInstanceOf(Error);
    });

    it("defaults data to null", () => {
        expect(new ApiError(Codes.NOT_FOUND).data).toBeNull();
    });
});
