import { Codes } from "./codes";
import { ApiError } from "./response";

const AUTHORIZE_URL = "https://github.com/login/oauth/authorize";
const ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token";
const USER_URL = "https://api.github.com/user";
/** A hung GitHub call must fail the login, not hang it. */
const GITHUB_TIMEOUT_MS = 10_000;

function requireEnv(name: string): string {
    const value = process.env[name];
    if (!value) {
        throw new Error(`${name} is not set`);
    }
    return value;
}

export function buildGithubAuthUrl(state: string): string {
    const params = new URLSearchParams({
        client_id: requireEnv("GITHUB_CLIENT_ID"),
        redirect_uri: requireEnv("GITHUB_REDIRECT_URI"),
        scope: "read:user",
        state,
    });
    return `${AUTHORIZE_URL}?${params.toString()}`;
}

export async function exchangeCodeForToken(code: string): Promise<string> {
    // Resolve config before the fetch: a missing env var is a server
    // misconfiguration, not an unreachable-provider error.
    const clientId = requireEnv("GITHUB_CLIENT_ID");
    const clientSecret = requireEnv("GITHUB_CLIENT_SECRET");
    const redirectUri = requireEnv("GITHUB_REDIRECT_URI");
    let res: Response;
    try {
        res = await fetch(ACCESS_TOKEN_URL, {
            method: "POST",
            headers: {
                Accept: "application/json",
                "Content-Type": "application/json",
                "User-Agent": "jawbts-api",
            },
            body: JSON.stringify({
                client_id: clientId,
                client_secret: clientSecret,
                redirect_uri: redirectUri,
                code,
            }),
            signal: AbortSignal.timeout(GITHUB_TIMEOUT_MS),
        });
    } catch {
        throw new ApiError(Codes.OAUTH_FAILED, {
            where: "GitHub token exchange",
            message: "Could not reach GitHub",
        });
    }
    const body = (await res.json().catch(() => null)) as {
        access_token?: string;
        error?: string;
        error_description?: string;
    } | null;
    if (!res.ok || !body?.access_token) {
        throw new ApiError(Codes.OAUTH_FAILED, {
            where: "GitHub token exchange",
            message:
                body?.error_description ??
                body?.error ??
                `GitHub rejected the authorization code (HTTP ${res.status})`,
        });
    }
    return body.access_token;
}

export async function fetchGithubUser(accessToken: string): Promise<{ id: number; login: string }> {
    let res: Response;
    try {
        res = await fetch(USER_URL, {
            headers: {
                Accept: "application/vnd.github+json",
                Authorization: `Bearer ${accessToken}`,
                "User-Agent": "jawbts-api",
            },
            signal: AbortSignal.timeout(GITHUB_TIMEOUT_MS),
        });
    } catch {
        throw new ApiError(Codes.OAUTH_FAILED, {
            where: "GitHub user lookup",
            message: "Could not reach GitHub",
        });
    }
    const body = (await res.json().catch(() => null)) as {
        id?: number;
        login?: string;
        message?: string;
    } | null;
    if (!res.ok || typeof body?.id !== "number") {
        throw new ApiError(Codes.OAUTH_FAILED, {
            where: "GitHub user lookup",
            message: body?.message ?? `GitHub user lookup failed (HTTP ${res.status})`,
        });
    }
    return { id: body.id, login: body.login ?? "" };
}
