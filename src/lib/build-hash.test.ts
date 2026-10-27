import { describe, expect, it } from "vitest";
import { BUILD_HASH_HEADER, resolveBuildHash } from "./build-hash";

describe("build hash", () => {
    it("uses an explicit BUILD_HASH first", () => {
        expect(
            resolveBuildHash({
                BUILD_HASH: "abc123",
                VERCEL_GIT_COMMIT_SHA: "vercel",
                GITHUB_SHA: "github",
            }),
        ).toBe("abc123");
    });

    it("falls back to Vercel, then GitHub, then dev", () => {
        expect(
            resolveBuildHash({ VERCEL_GIT_COMMIT_SHA: "vercel" }),
        ).toBe("vercel");
        expect(resolveBuildHash({ GITHUB_SHA: "github" })).toBe(
            "github",
        );
        expect(resolveBuildHash({})).toBe("dev");
    });

    it("uses a stable response header name", () => {
        expect(BUILD_HASH_HEADER).toBe("X-Build-Hash");
    });
});
