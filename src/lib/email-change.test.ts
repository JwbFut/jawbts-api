import { describe, expect, it } from "vitest";
import {
    decodeEmailChangePlaceholder,
    EMAIL_CHANGE_COOLDOWN_MS,
    EMAIL_CHANGE_TTL_MS,
    encodeEmailChangePlaceholder,
    isPlaceholderEmail,
} from "./email-change";

describe("email-change placeholder", () => {
    it("round-trips from/to/expiry and is never a real address", () => {
        const expiresAt = new Date(Date.now() + EMAIL_CHANGE_TTL_MS);
        const encoded = encodeEmailChangePlaceholder({
            from: "old@example.com",
            to: "new@example.com",
            expiresAt,
        });
        expect(isPlaceholderEmail(encoded)).toBe(true);
        expect(encoded).toContain("@placeholder.jawbts.org");
        expect(decodeEmailChangePlaceholder(encoded)).toEqual({
            from: "old@example.com",
            to: "new@example.com",
            expiresAt,
        });
    });

    it("uses a fresh nonce per placeholder", () => {
        const change = {
            from: "old@example.com",
            to: "new@example.com",
            expiresAt: new Date(Date.now() + 1000),
        };
        expect(encodeEmailChangePlaceholder(change)).not.toBe(
            encodeEmailChangePlaceholder(change),
        );
    });

    it("rejects real emails and malformed placeholders", () => {
        expect(decodeEmailChangePlaceholder("a@b.com")).toBeNull();
        expect(decodeEmailChangePlaceholder(null)).toBeNull();
        expect(
            decodeEmailChangePlaceholder("change.%%%@placeholder.jawbts.org"),
        ).toBeNull();
        expect(
            decodeEmailChangePlaceholder("pending-1@placeholder.jawbts.org"),
        ).toBeNull();
    });

    it("exposes a short cooldown relative to the token lifetime", () => {
        expect(EMAIL_CHANGE_COOLDOWN_MS).toBe(60_000);
        expect(EMAIL_CHANGE_TTL_MS).toBe(24 * 60 * 60 * 1000);
    });
});
