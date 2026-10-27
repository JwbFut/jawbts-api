import { describe, expect, it } from "vitest";
import { request } from "@/test/request";
import { DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT } from "./route";

describe("catch-all 404", () => {
    it("returns the 10000 envelope for an unknown path", async () => {
        const res = await GET(request("http://localhost/whatever"), {});
        expect(res.status).toBe(404);
        expect(await res.json()).toEqual({
            success: false,
            code: 10000,
            message: "Not Found",
            data: null,
        });
    });

    it("returns JSON, not HTML", async () => {
        const res = await GET(request("http://localhost/whatever"), {});
        expect(res.headers.get("content-type")).toContain("application/json");
    });

    it.each([
        ["POST", POST],
        ["PUT", PUT],
        ["PATCH", PATCH],
        ["DELETE", DELETE],
        ["HEAD", HEAD],
    ] as const)("returns 404 for %s as well", async (_method, handler) => {
        const res = await handler(request("http://localhost/a/b/c"), {});
        expect(res.status).toBe(404);
    });

    it("answers OPTIONS as a 204 preflight, not 404", () => {
        const res = OPTIONS();
        expect(res.status).toBe(204);
        expect(res.headers.get("access-control-allow-origin")).toBe("*");
    });
});
