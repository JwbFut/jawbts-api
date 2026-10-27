/** Response header carrying the deployed build/commit hash. */
export const BUILD_HASH_HEADER = "X-Build-Hash";

/**
 * Prefer an explicit build hash (CI/Vercel build env), then the platform's
 * commit SHA, then a local-dev marker. The value is baked into next.config at
 * build time, so it is identical for every response from that deployment.
 */
export function resolveBuildHash(env: Record<string, string | undefined> = process.env): string {
    return (
        env.BUILD_HASH?.trim() ||
        env.VERCEL_GIT_COMMIT_SHA?.trim() ||
        env.GITHUB_SHA?.trim() ||
        "dev"
    );
}

export const BUILD_HASH = resolveBuildHash();
