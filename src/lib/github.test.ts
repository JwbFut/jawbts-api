import { afterEach, describe, expect, it, vi } from "vitest";
import { Codes } from "./codes";
import { exchangeCodeForToken, fetchGithubUser } from "./github";

afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
});

function stubGithubEnv(): void {
    vi.stubEnv("GITHUB_CLIENT_ID", "client-id");
    vi.stubEnv("GITHUB_CLIENT_SECRET", "client-secret");
    vi.stubEnv("GITHUB_REDIRECT_URI", "https://example.com/callback");
}

describe("GitHub network failures are fail-safe", () => {
    it("maps an unreachable token exchange to 10009 instead of 500", async () => {
        stubGithubEnv();
        vi.stubGlobal("fetch", vi.fn(async () => {
            throw new DOMException("The operation was aborted", "TimeoutError");
        }));
        await expect(exchangeCodeForToken("code")).rejects.toMatchObject({
            code: Codes.OAUTH_FAILED,
            data: { where: "GitHub token exchange", message: "Could not reach GitHub" },
        });
    });

    it("maps an unreachable user lookup to 10009", async () => {
        vi.stubGlobal("fetch", vi.fn(async () => {
            throw new TypeError("fetch failed");
        }));
        await expect(fetchGithubUser("token")).rejects.toMatchObject({
            code: Codes.OAUTH_FAILED,
            data: { where: "GitHub user lookup", message: "Could not reach GitHub" },
        });
    });

    it("passes an abort timeout with every GitHub request", async () => {
        stubGithubEnv();
        const fetchMock = vi.fn(async () =>
            new Response(JSON.stringify({ access_token: "gh-token" }), { status: 200 }),
        );
        vi.stubGlobal("fetch", fetchMock);
        await exchangeCodeForToken("code");
        const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
        expect(init.signal).toBeInstanceOf(AbortSignal);
    });

    it("surfaces a missing OAuth config as a server error, not a network error", async () => {
        vi.stubEnv("GITHUB_CLIENT_ID", "");
        const fetchMock = vi.fn();
        vi.stubGlobal("fetch", fetchMock);
        await expect(exchangeCodeForToken("code")).rejects.toThrow("GITHUB_CLIENT_ID is not set");
        expect(fetchMock).not.toHaveBeenCalled();
    });
});
