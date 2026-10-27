import { describe, expect, it } from "vitest";
import nextConfig from "../../next.config";
import { CORS_HEADERS, corsPreflight } from "./cors";

describe("CORS", () => {
    it("applies wildcard headers to every path via next.config", async () => {
        const rules = await nextConfig.headers?.();
        expect(rules).toHaveLength(1);
        expect(rules?.[0].source).toBe("/:path*");
        expect(rules?.[0].headers).toEqual(
            Object.entries(CORS_HEADERS).map(([key, value]) => ({ key, value })),
        );
        expect(CORS_HEADERS["Access-Control-Allow-Origin"]).toBe("*");
        expect(CORS_HEADERS["Access-Control-Allow-Credentials"]).toBeUndefined();
    });

    it("answers preflight with 204 and the same headers", () => {
        const res = corsPreflight();
        expect(res.status).toBe(204);
        expect(res.headers.get("access-control-allow-origin")).toBe("*");
        expect(res.headers.get("access-control-allow-headers")).toContain("Authorization");
        expect(res.headers.get("access-control-allow-credentials")).toBeNull();
    });
});
