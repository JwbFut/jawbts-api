/**
 * Permission catalog. A token's `scope` claim is its list of permissions.
 *
 * - `api` is the internal scope for account/session endpoints. It is only put
 *   on tokens minted by the GitHub-login refresh exchange and is never
 *   grantable to a user row or delegable.
 * - `issue_tokens` is the GitHub-only marker: the GitHub-login refresh
 *   exchange adds it when the user holds it, and it is never delegable, so
 *   only tokens derived from a GitHub login can ever carry it (a delegated
 *   refresh never adds it). `/auth/token` requires it.
 * - `play_sequence_override` is a normal user permission (music player) and is
 *   delegable.
 */
export const Permissions = {
    API: "api",
    ISSUE_TOKENS: "issue_tokens",
    PLAY_SEQUENCE_OVERRIDE: "play_sequence_override",
} as const;

export type Permission = (typeof Permissions)[keyof typeof Permissions];

/** Permissions that may be stored on a user row (never `api`). */
export const USER_PERMISSIONS = [
    Permissions.ISSUE_TOKENS,
    Permissions.PLAY_SEQUENCE_OVERRIDE,
] as const;

export type UserPermission = (typeof USER_PERMISSIONS)[number];

/** Permissions a minted token may carry (least privilege: no issue_tokens/api). */
const DELEGABLE = new Set<string>([Permissions.PLAY_SEQUENCE_OVERRIDE]);

export function isUserPermission(value: string): value is UserPermission {
    return (USER_PERMISSIONS as readonly string[]).includes(value);
}

export function isDelegablePermission(value: string): boolean {
    return DELEGABLE.has(value);
}

/**
 * The scope of a token derived from a GitHub login: the account-management
 * `api` scope plus the mint marker `issue_tokens` when the user holds it.
 * Other user permissions (e.g. play_sequence_override) are delegated-only and
 * are never put on this token.
 */
export function githubTokenScope(userPermissions: readonly string[]): string[] {
    const scope: string[] = [Permissions.API];
    if (userPermissions.includes(Permissions.ISSUE_TOKENS)) {
        scope.push(Permissions.ISSUE_TOKENS);
    }
    return scope;
}
