import { afterEach, describe, expect, it, vi } from "vitest";
import { request } from "@/test/request";
import { getRemoteJwks, resetRemoteJwksForTests } from "./jwks-remote";

afterEach(() => {
    resetRemoteJwksForTests();
    vi.unstubAllEnvs();
});

describe("getRemoteJwks", () => {
    it("requires JWKS_ORIGIN in production", () => {
        vi.stubEnv("NODE_ENV", "production");
        vi.stubEnv("JWKS_ORIGIN", "");
        expect(() => getRemoteJwks(request("https://evil.example/x"))).toThrow(
            "JWKS_ORIGIN is required in production",
        );
    });

    it("rejects non-http(s) JWKS_ORIGIN", () => {
        vi.stubEnv("NODE_ENV", "production");
        vi.stubEnv("JWKS_ORIGIN", "ftp://example.com");
        expect(() => getRemoteJwks(request("https://evil.example/x"))).toThrow(
            "JWKS_ORIGIN must use http: or https:",
        );
    });

    it("uses the configured origin instead of the request host", () => {
        vi.stubEnv("NODE_ENV", "production");
        vi.stubEnv("JWKS_ORIGIN", "https://api.example.com/path");
        const set = getRemoteJwks(request("https://evil.example/x"));
        expect(set).toBeTruthy();
    });
});
