import { beforeEach, describe, expect, it, vi } from "vitest";
import {
    encodeEmailChangePlaceholder,
    generateEmailChangeToken,
    hashEmailChangeToken,
    isPlaceholderEmail,
} from "@/lib/email-change";
import { request } from "@/test/request";
import { POST as confirmEmailChange } from "./route";

interface UserRow {
    id: number;
    email: string;
    emailChangeTokenHash: string | null;
    emailChangeExpiresAt: Date | null;
}

const { fakeDb, userMock, users } = vi.hoisted(() => {
    const users: UserRow[] = [];
    const userMock = {
        findMany: vi.fn(
            async ({ where }: { where: { emailChangeTokenHash: string } }) =>
                users.filter((u) => u.emailChangeTokenHash === where.emailChangeTokenHash),
        ),
        findFirst: vi.fn(),
        updateMany: vi.fn(
            async ({
                where,
                data,
            }: {
                where: { id: number; emailChangeTokenHash: string; email?: string };
                data: Partial<UserRow>;
            }) => {
                const user = users.find(
                    (u) =>
                        u.id === where.id &&
                        u.emailChangeTokenHash === where.emailChangeTokenHash &&
                        (where.email === undefined || u.email === where.email),
                );
                if (!user) {
                    return { count: 0 };
                }
                Object.assign(user, data);
                return { count: 1 };
            },
        ),
    };
    return { fakeDb: { user: userMock }, userMock, users };
});

vi.mock("@/lib/prisma", () => ({ getPrisma: async () => fakeDb }));

function makeUser(overrides: Partial<UserRow> = {}): UserRow {
    return {
        id: 1,
        email: encodeEmailChangePlaceholder({
            from: "old@example.com",
            to: "new@example.com",
            expiresAt: new Date(Date.now() + 60_000),
        }),
        emailChangeTokenHash: "seed-hash",
        emailChangeExpiresAt: new Date(Date.now() + 60_000),
        ...overrides,
    };
}

beforeEach(() => {
    vi.clearAllMocks();
    users.length = 0;
    userMock.findFirst.mockResolvedValue(null);
});

function post(token: unknown) {
    return request("http://localhost/auth/email/confirm", {
        method: "POST",
        body: JSON.stringify({ token }),
    });
}

describe("POST /auth/email/confirm", () => {
    it("rejects an unknown or already used token", async () => {
        const res = await confirmEmailChange(post(generateEmailChangeToken()), {});
        expect(res.status).toBe(401);
        expect((await res.json()).code).toBe(10006);
    });

    it("expires without restoring the old address", async () => {
        const token = generateEmailChangeToken();
        const user = makeUser({
            emailChangeTokenHash: await hashEmailChangeToken(token),
            emailChangeExpiresAt: new Date(Date.now() - 60_000),
        });
        users.push(user);
        const res = await confirmEmailChange(post(token), {});
        expect(res.status).toBe(401);
        expect((await res.json()).code).toBe(10005);
        expect(isPlaceholderEmail(user.email)).toBe(true);
        expect(user.emailChangeTokenHash).toBeNull();
        expect(user.emailChangeExpiresAt).toBeNull();
    });

    it("clears on a conflict without restoring the old address", async () => {
        const token = generateEmailChangeToken();
        const user = makeUser({ emailChangeTokenHash: await hashEmailChangeToken(token) });
        users.push(user);
        userMock.findFirst.mockResolvedValue({ id: 2, email: "new@example.com" });
        const res = await confirmEmailChange(post(token), {});
        expect(res.status).toBe(400);
        expect((await res.json()).data.message).toBe("Email already exists");
        expect(isPlaceholderEmail(user.email)).toBe(true);
        expect(user.emailChangeTokenHash).toBeNull();
    });

    it("confirms the encoded address and clears the token", async () => {
        const token = generateEmailChangeToken();
        const user = makeUser({ emailChangeTokenHash: await hashEmailChangeToken(token) });
        users.push(user);
        const res = await confirmEmailChange(post(token), {});
        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.data).toEqual({ confirmed: true, email: "new@example.com" });
        expect(user.email).toBe("new@example.com");
        expect(user.emailChangeTokenHash).toBeNull();
        expect(user.emailChangeExpiresAt).toBeNull();
    });

    it("rejects a malformed placeholder state and clears it", async () => {
        const token = generateEmailChangeToken();
        const user = makeUser({
            email: "old@example.com",
            emailChangeTokenHash: await hashEmailChangeToken(token),
        });
        users.push(user);
        const res = await confirmEmailChange(post(token), {});
        expect(res.status).toBe(401);
        expect((await res.json()).code).toBe(10006);
        expect(user.email).toBe("old@example.com");
        expect(user.emailChangeTokenHash).toBeNull();
    });

    it("treats a superseded token as invalid", async () => {
        const token = generateEmailChangeToken();
        users.push(makeUser({ emailChangeTokenHash: await hashEmailChangeToken(token) }));
        userMock.updateMany.mockResolvedValueOnce({ count: 0 });
        const res = await confirmEmailChange(post(token), {});
        expect(res.status).toBe(401);
        expect((await res.json()).code).toBe(10006);
    });

    it("clears state when the final update hits a unique violation", async () => {
        const token = generateEmailChangeToken();
        const user = makeUser({ emailChangeTokenHash: await hashEmailChangeToken(token) });
        users.push(user);
        userMock.updateMany.mockRejectedValueOnce(
            Object.assign(new Error("dup"), { code: "P2002" }),
        );
        const res = await confirmEmailChange(post(token), {});
        expect(res.status).toBe(400);
        expect((await res.json()).data.message).toBe("Email already exists");
        expect(user.emailChangeTokenHash).toBeNull();
        expect(isPlaceholderEmail(user.email)).toBe(true);
    });

    it("rejects a missing or too-short token", async () => {
        const res = await confirmEmailChange(post("short"), {});
        expect(res.status).toBe(400);
        expect((await res.json()).code).toBe(10001);
    });
});
