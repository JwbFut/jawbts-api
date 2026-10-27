import { createHash } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
    ACTIVITY_WINDOW_MS,
    DEFAULT_ALERT_FROM,
    RESEND_ENDPOINT,
    activityHashInput,
    buildActivityAlert,
    hashActivity,
    recordActivity,
    sendActivityAlert,
    type ActivityEvent,
} from "./activity";
import { Codes } from "./codes";
import { ApiError } from "./response";
import type { Db } from "./sessions";

interface HashRow {
    id: string;
    userId: number;
    hash: string;
    createdAt: Date;
}

function makeDb(seed: HashRow[] = []) {
    const rows = [...seed];
    let seq = 0;
    const findFirst = vi.fn(
        async ({
            where,
        }: {
            where: { userId: number; hash: string; createdAt: { gte: Date } };
        }) =>
            rows.find(
                (row) =>
                    row.userId === where.userId &&
                    row.hash === where.hash &&
                    row.createdAt >= where.createdAt.gte,
            ) ?? null,
    );
    const create = vi.fn(async ({ data }: { data: { userId: number; hash: string } }) => {
        const row: HashRow = { id: `h${++seq}`, createdAt: new Date(), ...data };
        rows.push(row);
        return row;
    });
    const deleteMany = vi.fn(async ({ where }: { where: { createdAt: { lt: Date } } }) => {
        let count = 0;
        for (let i = rows.length - 1; i >= 0; i--) {
            if (rows[i].createdAt < where.createdAt.lt) {
                rows.splice(i, 1);
                count++;
            }
        }
        return { count };
    });
    return { db: { activityHash: { findFirst, create, deleteMany } } as unknown as Db, rows };
}

function jsonResponse(body: unknown, status = 200): Response {
    return new Response(JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json" },
    });
}

let fetchMock: ReturnType<typeof vi.fn>;
let consoleError: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
    vi.stubEnv("RESEND_API_KEY", "re_test_key");
    vi.stubEnv("ACTIVITY_HASH_SALT", "test-salt");
    consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    fetchMock = vi.fn(async () => jsonResponse({ id: "email-1" }));
    vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
    consoleError.mockRestore();
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
});

describe("hashActivity", () => {
    it("is a deterministic salted SHA-512 digest (128 hex chars)", async () => {
        const expected = createHash("sha512")
            .update(`test-salt\n${activityHashInput("203.0.113.7", "Firefox/120")}`)
            .digest("hex");
        const hash = await hashActivity("203.0.113.7", "Firefox/120");
        expect(hash).toBe(expected);
        expect(hash).toMatch(/^[0-9a-f]{128}$/);
        expect(await hashActivity("203.0.113.7", "Firefox/120")).toBe(hash);
    });

    it("depends on the configured salt", async () => {
        const withSalt = await hashActivity("203.0.113.7", "Firefox/120");
        vi.stubEnv("ACTIVITY_HASH_SALT", "another-salt");
        expect(await hashActivity("203.0.113.7", "Firefox/120")).not.toBe(withSalt);
    });

    it("fails closed when the salt is missing", async () => {
        vi.stubEnv("ACTIVITY_HASH_SALT", "");
        await expect(hashActivity("203.0.113.7", "Firefox/120")).rejects.toThrow(
            "ACTIVITY_HASH_SALT is not set",
        );
    });

    it("changes when either the IP or the user agent changes", async () => {
        const base = await hashActivity("203.0.113.7", "Firefox/120");
        expect(await hashActivity("203.0.113.8", "Firefox/120")).not.toBe(base);
        expect(await hashActivity("203.0.113.7", "Firefox/121")).not.toBe(base);
    });

    it("separates fields unambiguously", async () => {
        expect(await hashActivity("1.2.3.4", "a|b")).not.toBe(
            await hashActivity("1.2.3.4|a", "b"),
        );
    });
});

describe("buildActivityAlert", () => {
    const at = new Date("2025-02-03T04:05:06.000Z");

    it("includes the IP, user agent and timestamp", () => {
        const alert = buildActivityAlert({
            to: "alice@example.com",
            ip: "203.0.113.7",
            userAgent: "Firefox/120",
            kind: "login",
            at,
        });
        expect(alert.subject).toBe("New login to your jawbts account");
        expect(alert.text).toContain("203.0.113.7");
        expect(alert.text).toContain("Firefox/120");
        expect(alert.text).toContain(at.toISOString());
        expect(alert.html).toContain("203.0.113.7");
        expect(alert.html).toContain("Firefox/120");
    });

    it("uses a different subject for refresh activity", () => {
        const alert = buildActivityAlert({
            to: "alice@example.com",
            ip: "203.0.113.7",
            userAgent: "Firefox/120",
            kind: "refresh",
            at,
        });
        expect(alert.subject).toBe("New activity on your jawbts account");
        expect(alert.text).toContain("refresh token");
    });

    it("escapes header-derived values in the HTML body", () => {
        const alert = buildActivityAlert({
            to: "alice@example.com",
            ip: "203.0.113.7",
            userAgent: "<script>alert(\"x\")</script>",
            kind: "login",
            at,
        });
        expect(alert.html).not.toContain("<script>");
        expect(alert.html).toContain("&lt;script&gt;");
        expect(alert.text).toContain("<script>alert(\"x\")</script>");
    });
});

describe("sendActivityAlert", () => {
    const alert = {
        to: "alice@example.com",
        ip: "203.0.113.7",
        userAgent: "Firefox/120",
        kind: "login" as const,
        at: new Date("2025-02-03T04:05:06.000Z"),
    };

    it("uses the Api Bot sender by default", () => {
        expect(DEFAULT_ALERT_FROM).toBe("Api Bot <api-bot@noreply.jawbts.org>");
    });

    it("posts to Resend with the configured sender", async () => {
        await sendActivityAlert(alert);
        expect(fetchMock).toHaveBeenCalledTimes(1);
        const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
        expect(url).toBe(RESEND_ENDPOINT);
        expect(init.method).toBe("POST");
        expect((init.headers as Record<string, string>).Authorization).toBe("Bearer re_test_key");
        const body = JSON.parse(String(init.body)) as {
            from: string;
            to: string[];
            subject: string;
            text: string;
        };
        expect(body.from).toBe(DEFAULT_ALERT_FROM);
        expect(body.to).toEqual(["alice@example.com"]);
        expect(body.subject).toContain("login");
        expect(body.text).toContain("203.0.113.7");
    });

    it("honours RESEND_FROM", async () => {
        vi.stubEnv("RESEND_FROM", "alerts@jawbts.org");
        await sendActivityAlert(alert);
        const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
        expect(JSON.parse(String(init.body)).from).toBe("alerts@jawbts.org");
    });

    it("falls back to the default sender when RESEND_FROM is blank", async () => {
        vi.stubEnv("RESEND_FROM", "   ");
        await sendActivityAlert(alert);
        const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
        expect(JSON.parse(String(init.body)).from).toBe(DEFAULT_ALERT_FROM);
    });

    it("fails with 10012 when RESEND_API_KEY is missing", async () => {
        vi.stubEnv("RESEND_API_KEY", "");
        await expect(sendActivityAlert(alert)).rejects.toMatchObject({
            code: Codes.ACTIVITY_ALERT_FAILED,
        });
        expect(fetchMock).not.toHaveBeenCalled();
    });

    it("fails with 10012 on a non-2xx provider response", async () => {
        fetchMock.mockResolvedValueOnce(jsonResponse({ message: "invalid from" }, 422));
        const error = await sendActivityAlert(alert).catch((e: unknown) => e);
        expect(error).toBeInstanceOf(ApiError);
        expect((error as ApiError).code).toBe(Codes.ACTIVITY_ALERT_FAILED);
        expect((error as ApiError).data).toMatchObject({
            message: "Email provider rejected the alert (HTTP 422)",
        });
    });

    it("fails with 10012 when the provider is unreachable", async () => {
        fetchMock.mockRejectedValueOnce(new TypeError("fetch failed"));
        await expect(sendActivityAlert(alert)).rejects.toMatchObject({
            code: Codes.ACTIVITY_ALERT_FAILED,
        });
    });
});

describe("recordActivity", () => {
    const event: ActivityEvent = {
        userId: 1,
        email: "alice@example.com",
        ip: "203.0.113.7",
        userAgent: "Firefox/120",
        kind: "login",
    };

    it("emails and stores the hash for a new fingerprint", async () => {
        const { db, rows } = makeDb();
        await recordActivity(db, event);
        expect(fetchMock).toHaveBeenCalledTimes(1);
        expect(rows).toHaveLength(1);
        expect(rows[0].userId).toBe(1);
        expect(rows[0].hash).toBe(await hashActivity(event.ip, event.userAgent));
        expect(rows[0].createdAt).toBeInstanceOf(Date);
    });

    it("records every event but emails only once inside the 7-day window", async () => {
        const { db, rows } = makeDb();
        await recordActivity(db, event);
        await recordActivity(db, event);
        await recordActivity(db, { ...event, kind: "refresh" });
        expect(fetchMock).toHaveBeenCalledTimes(1);
        expect(rows).toHaveLength(3);
    });

    it("emails again once the previous row is older than the window", async () => {
        const old: HashRow = {
            id: "old",
            userId: 1,
            hash: await hashActivity(event.ip, event.userAgent),
            createdAt: new Date(Date.now() - ACTIVITY_WINDOW_MS - 1000),
        };
        const { db } = makeDb([old]);
        await recordActivity(db, event);
        expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it("prunes rows older than the window on every event", async () => {
        const now = Date.now();
        const old: HashRow = {
            id: "old",
            userId: 9,
            hash: "stale-hash",
            createdAt: new Date(now - ACTIVITY_WINDOW_MS - 1000),
        };
        const fresh: HashRow = {
            id: "fresh",
            userId: 2,
            hash: "fresh-hash",
            createdAt: new Date(now - 1000),
        };
        const { db, rows } = makeDb([old, fresh]);
        await recordActivity(db, event);
        expect(rows.map((row) => row.id)).not.toContain("old");
        expect(rows.map((row) => row.id)).toContain("fresh");
        // The pruned fingerprint counts as unseen, so an alert is sent.
        expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it("scopes the 7-day window to the user", async () => {
        const otherUser: HashRow = {
            id: "other",
            userId: 2,
            hash: await hashActivity(event.ip, event.userAgent),
            createdAt: new Date(),
        };
        const { db } = makeDb([otherUser]);
        await recordActivity(db, event);
        expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it("skips the email (but still stores) when the account has no email", async () => {
        const { db, rows } = makeDb();
        await recordActivity(db, { ...event, email: null });
        expect(fetchMock).not.toHaveBeenCalled();
        expect(rows).toHaveLength(1);
    });

    it("treats a blank email as absent", async () => {
        const { db, rows } = makeDb();
        await recordActivity(db, { ...event, email: "   " });
        expect(fetchMock).not.toHaveBeenCalled();
        expect(rows).toHaveLength(1);
    });

    it("still records the event when retention cleanup fails", async () => {
        const { db, rows } = makeDb();
        vi.mocked(db.activityHash.deleteMany).mockRejectedValueOnce(new Error("cleanup failed"));
        await recordActivity(db, event);
        expect(fetchMock).toHaveBeenCalledTimes(1);
        expect(rows).toHaveLength(1);
    });

    it("fails and stores nothing when the alert email cannot be sent", async () => {
        const { db, rows } = makeDb();
        fetchMock.mockResolvedValueOnce(jsonResponse({ message: "boom" }, 500));
        await expect(recordActivity(db, event)).rejects.toMatchObject({
            code: Codes.ACTIVITY_ALERT_FAILED,
        });
        expect(rows).toHaveLength(0);
    });
});
