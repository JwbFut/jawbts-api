import { describe, expect, it } from "vitest";
import { CodeInfo, Codes } from "./codes";

describe("codes", () => {
    it("exposes the built-in code values", () => {
        expect(Codes.SUCCESS).toBe(200);
        expect(Codes.NOT_FOUND).toBe(10000);
        expect(Codes.BAD_REQUEST).toBe(10001);
        expect(Codes.UNAUTHORIZED).toBe(10002);
        expect(Codes.FORBIDDEN).toBe(10003);
        expect(Codes.SESSION_LIMIT).toBe(10004);
        expect(Codes.TOKEN_EXPIRED).toBe(10005);
        expect(Codes.TOKEN_INVALID).toBe(10006);
        expect(Codes.INSUFFICIENT_SCOPE).toBe(10007);
        expect(Codes.USER_NOT_FOUND).toBe(10008);
        expect(Codes.OAUTH_FAILED).toBe(10009);
        expect(Codes.IDENTITY_MISMATCH).toBe(10010);
        expect(Codes.OAUTH_STATE_INVALID).toBe(10011);
        expect(Codes.ACTIVITY_ALERT_FAILED).toBe(10012);
        expect(Codes.NOTIFICATION_FAILED).toBe(10013);
        expect(Codes.RATE_LIMITED).toBe(10014);
        expect(Codes.EMAIL_CHANGE_STATE_INVALID).toBe(10015);
        expect(Codes.INTERNAL_ERROR).toBe(10500);
    });

    it("maps every code to a message and an HTTP status", () => {
        for (const code of Object.values(Codes)) {
            const info = CodeInfo[code];
            expect(info).toBeDefined();
            expect(typeof info.message).toBe("string");
            expect(info.status).toBeGreaterThanOrEqual(200);
            expect(info.status).toBeLessThan(600);
        }
    });

    it("maps codes to the documented HTTP statuses", () => {
        expect(CodeInfo[Codes.SUCCESS].status).toBe(200);
        expect(CodeInfo[Codes.NOT_FOUND].status).toBe(404);
        expect(CodeInfo[Codes.BAD_REQUEST].status).toBe(400);
        expect(CodeInfo[Codes.UNAUTHORIZED].status).toBe(401);
        expect(CodeInfo[Codes.FORBIDDEN].status).toBe(403);
        expect(CodeInfo[Codes.SESSION_LIMIT].status).toBe(429);
        expect(CodeInfo[Codes.TOKEN_EXPIRED].status).toBe(401);
        expect(CodeInfo[Codes.TOKEN_INVALID].status).toBe(401);
        expect(CodeInfo[Codes.INSUFFICIENT_SCOPE].status).toBe(403);
        expect(CodeInfo[Codes.USER_NOT_FOUND].status).toBe(404);
        expect(CodeInfo[Codes.OAUTH_FAILED].status).toBe(401);
        expect(CodeInfo[Codes.IDENTITY_MISMATCH].status).toBe(403);
        expect(CodeInfo[Codes.OAUTH_STATE_INVALID].status).toBe(400);
        expect(CodeInfo[Codes.ACTIVITY_ALERT_FAILED].status).toBe(502);
        expect(CodeInfo[Codes.NOTIFICATION_FAILED].status).toBe(502);
        expect(CodeInfo[Codes.RATE_LIMITED].status).toBe(429);
        expect(CodeInfo[Codes.EMAIL_CHANGE_STATE_INVALID].status).toBe(409);
        expect(CodeInfo[Codes.INTERNAL_ERROR].status).toBe(500);
    });

    it("treats only SUCCESS as a non-error status", () => {
        expect(CodeInfo[Codes.SUCCESS].status).toBeLessThan(400);
        for (const code of Object.values(Codes)) {
            if (code !== Codes.SUCCESS) {
                expect(CodeInfo[code].status).toBeGreaterThanOrEqual(400);
            }
        }
    });
});
