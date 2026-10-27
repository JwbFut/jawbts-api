import { describe, expect, it } from "vitest";
import catalog from "./permissions.json";
import {
    githubTokenScope,
    isDelegablePermission,
    isUserPermission,
    Permissions,
    USER_PERMISSIONS,
} from "./permissions";

describe("permission catalog", () => {
    it("keeps the shared JSON catalog in sync with the TypeScript catalog", () => {
        expect(catalog.user).toEqual([...USER_PERMISSIONS]);
    });

    it("classifies user permissions", () => {
        expect(isUserPermission(Permissions.ISSUE_TOKENS)).toBe(true);
        expect(isUserPermission(Permissions.PLAY_SEQUENCE_OVERRIDE)).toBe(true);
        expect(isUserPermission(Permissions.API)).toBe(false);
        expect(isUserPermission("unknown_permission")).toBe(false);
    });

    it("never delegates token issuance or the api scope", () => {
        expect(isDelegablePermission(Permissions.PLAY_SEQUENCE_OVERRIDE)).toBe(true);
        expect(isDelegablePermission(Permissions.ISSUE_TOKENS)).toBe(false);
        expect(isDelegablePermission(Permissions.API)).toBe(false);
    });
});

describe("githubTokenScope", () => {
    it("includes only api and issue_tokens, never delegated permissions", () => {
        expect(
            githubTokenScope([Permissions.ISSUE_TOKENS, Permissions.PLAY_SEQUENCE_OVERRIDE]),
        ).toEqual([Permissions.API, Permissions.ISSUE_TOKENS]);
    });

    it("omits issue_tokens when the user does not hold it", () => {
        expect(
            githubTokenScope([Permissions.PLAY_SEQUENCE_OVERRIDE, "unknown_permission"]),
        ).toEqual([Permissions.API]);
    });

    it("ignores duplicates and the internal api scope in the user row", () => {
        expect(
            githubTokenScope([
                Permissions.API,
                Permissions.ISSUE_TOKENS,
                Permissions.ISSUE_TOKENS,
            ]),
        ).toEqual([Permissions.API, Permissions.ISSUE_TOKENS]);
    });

    it("handles a user with no permissions", () => {
        expect(githubTokenScope([])).toEqual([Permissions.API]);
    });
});
