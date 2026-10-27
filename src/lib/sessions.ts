import { SessionType } from "@/generated/prisma/client";
import type { NextRequest } from "next/server";
import { bytesToBase64Url } from "./base64url";
import { Codes } from "./codes";
import { getPrisma, supportsTransactions } from "./prisma";
import { ApiError } from "./response";

export type Db = Awaited<ReturnType<typeof getPrisma>>;
/** The structural slice shared by PrismaClient and its transaction client. */
export type Tx = Pick<Db, "session" | "user">;

export const MAX_GITHUB_SESSIONS = 3;
/** Per-user cap on live delegated tokens. */
export const MAX_DELEGATED_TOKENS = 20;
export const REFRESH_TOKEN_TTL_SECONDS = 90 * 24 * 60 * 60;
export const REFRESH_TOKEN_TTL_MS = 1000 * REFRESH_TOKEN_TTL_SECONDS;
/** Delegated (minted) tokens: 1-day JWTs backed by a 90-day refresh token. */
export const DELEGATED_REFRESH_TOKEN_TTL_MS = REFRESH_TOKEN_TTL_MS;
/** A pending login (state issued, OAuth not yet finished) lives this long. */
export const PENDING_LOGIN_TTL_MS = 10 * 60 * 1000;

/**
 * Runs `run` inside a transaction when the active adapter allows it (the
 * WebSocket pool does). The Neon HTTP transport is stateless and its adapter
 * rejects transactions, so there it degrades to sequential statements.
 */
export async function inTx<R>(db: Db, run: (tx: Tx) => Promise<R>): Promise<R> {
    return supportsTransactions() ? db.$transaction(run) : run(db);
}

export async function sha256Hex(input: string): Promise<string> {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
    return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Opaque 256-bit refresh token; only its SHA-256 hash is persisted. */
export function generateRefreshToken(): string {
    return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

/**
 * The client IP as seen by the edge. Cloudflare is the only ingress (direct
 * origin access is firewalled), and `CF-Connecting-IP` is the header it sets
 * itself to the real client address. It must win over `X-Forwarded-For`:
 * Cloudflare preserves a client-supplied XFF, so its leftmost entry is
 * spoofable. XFF / X-Real-IP remain as fallbacks for local runs and tests.
 */
export function getClientIp(req: NextRequest): string {
    const connectingIp = req.headers.get("cf-connecting-ip")?.trim();
    if (connectingIp) {
        return connectingIp;
    }
    const forwarded = req.headers.get("x-forwarded-for");
    if (forwarded) {
        const first = forwarded.split(",")[0]?.trim();
        if (first) {
            return first;
        }
    }
    return req.headers.get("x-real-ip")?.trim() || "unknown";
}

/**
 * Cloudflare forwards the browser's `User-Agent` header unchanged — it has no
 * dedicated UA header of its own — so the standard header is the source.
 */
export function getUserAgent(req: NextRequest): string {
    return req.headers.get("user-agent")?.trim() || "unknown";
}

export async function pruneExpiredSessions(tx: Tx, userId: number): Promise<number> {
    const { count } = await tx.session.deleteMany({
        where: { userId, expiresAt: { lt: new Date() } },
    });
    return count;
}

export async function countActiveGithubSessions(tx: Tx, userId: number): Promise<number> {
    return tx.session.count({
        where: {
            userId,
            type: SessionType.GITHUB_LOGIN,
            expiresAt: { gte: new Date() },
        },
    });
}

/** Opaque 256-bit OAuth state; stored on the pending GITHUB_LOGIN row. */
export function generateState(): string {
    return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

export interface CreatedSession {
    refreshToken: string;
    sessionId: string;
    expiresAt: Date;
}

/**
 * Login step 1, one transaction: prune expired rows, enforce the per-user
 * GitHub-login cap, then write the pending GITHUB_LOGIN row carrying the
 * OAuth state (short TTL until the callback completes it).
 */
export async function startLoginSession(
    db: Db,
    args: { userId: number },
): Promise<{ state: string; sessionId: string }> {
    return inTx(db, async (tx) => {
        // Row lock: concurrent starts for the same user serialize here, so
        // two requests cannot both observe a free slot.
        await tx.user.update({
            where: { id: args.userId },
            data: { updatedAt: new Date() },
        });
        await pruneExpiredSessions(tx, args.userId);
        const active = await countActiveGithubSessions(tx, args.userId);
        if (active >= MAX_GITHUB_SESSIONS) {
            throw new ApiError(Codes.SESSION_LIMIT, {
                message: `Already ${active} active GitHub login sessions (max ${MAX_GITHUB_SESSIONS}); revoke one first`,
                active,
                limit: MAX_GITHUB_SESSIONS,
            });
        }
        const state = generateState();
        const login = await tx.session.create({
            data: {
                userId: args.userId,
                type: SessionType.GITHUB_LOGIN,
                state,
                expiresAt: new Date(Date.now() + PENDING_LOGIN_TTL_MS),
            },
        });
        return { state, sessionId: login.id };
    });
}

/** Validates an OAuth state and returns its pending GITHUB_LOGIN row. */
export async function findPendingLoginByState(db: Db, state: string): Promise<{ userId: number }> {
    const session = await db.session.findUnique({ where: { state } });
    if (!session || session.type !== SessionType.GITHUB_LOGIN || session.expiresAt <= new Date()) {
        throw new ApiError(Codes.OAUTH_STATE_INVALID, {
            message: "Invalid or expired OAuth state; start the login again",
        });
    }
    return session;
}

/**
 * Login step 2, one transaction: re-check the state (it is one-time), attach
 * the REFRESH_TOKEN child, then realize the GITHUB_LOGIN row — extend it to
 * the full refresh-token lifetime and consume the state.
 */
export async function completeLoginSession(
    db: Db,
    args: { state: string },
): Promise<CreatedSession> {
    return inTx(db, async (tx) => {
        const login = await tx.session.findUnique({ where: { state: args.state } });
        if (
            !login ||
            login.type !== SessionType.GITHUB_LOGIN ||
            login.expiresAt <= new Date()
        ) {
            throw new ApiError(Codes.OAUTH_STATE_INVALID, {
                message: "Invalid or expired OAuth state; start the login again",
            });
        }
        // Claim the one-time state before creating the refresh child. A
        // concurrent callback sees count 0 and cannot mint a second pair.
        const claimed = await tx.session.updateMany({
            where: { id: login.id, state: args.state },
            data: { state: null },
        });
        if (claimed.count === 0) {
            throw new ApiError(Codes.OAUTH_STATE_INVALID, {
                message: "OAuth state was already used or has expired",
            });
        }
        const expiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_MS);
        const refreshToken = generateRefreshToken();
        const child = await tx.session.create({
            data: {
                userId: login.userId,
                type: SessionType.REFRESH_TOKEN,
                refreshTokenHash: await sha256Hex(refreshToken),
                parentId: login.id,
                expiresAt,
            },
        });
        try {
            await tx.session.update({
                where: { id: login.id },
                data: { expiresAt },
            });
        } catch (error) {
            // On the HTTP transport there is no transaction to roll back. The
            // refresh token was never returned to the client, so remove the
            // now-orphaned row instead of leaving a valid token nobody holds.
            // With a real transaction the rollback below handles it.
            if (!supportsTransactions()) {
                try {
                    await tx.session.delete({ where: { id: child.id } });
                } catch (cleanupError) {
                    console.error("Login completion cleanup failed", cleanupError);
                }
            }
            throw error;
        }
        return { refreshToken, sessionId: login.id, expiresAt };
    });
}

/**
 * Deletes a session and its counterpart: revoking either row removes the
 * whole login pair (deleting the GITHUB_LOGIN parent cascades to its
 * REFRESH_TOKEN child). One statement, so atomic by itself.
 */
export async function revokeSessionTree(
    tx: Tx,
    session: { id: string; parentId: string | null },
): Promise<void> {
    // deleteMany keeps concurrent/expired/replayed revokes idempotent: a row
    // already removed by another request does not turn a 401 into a 500.
    await tx.session.deleteMany({ where: { id: session.parentId ?? session.id } });
}

/**
 * Case-insensitive lookup of a GitHub username. Fails closed when the
 * case-insensitive match is ambiguous (rows differing only by case), so a JWT
 * `sub` can never resolve to an arbitrary account.
 */
export async function findUserByName(db: Db, name: string) {
    const matches = await db.user.findMany({
        where: { name: { equals: name, mode: "insensitive" } },
        take: 2,
    });
    if (matches.length > 1) {
        throw new ApiError(Codes.IDENTITY_MISMATCH, {
            message: "Multiple accounts match this name; resolve the conflict before signing in",
        });
    }
    return matches[0] ?? null;
}

/**
 * Resolves a user from a GitHub username (JWT `sub` is the name, not the id).
 * Matched case-insensitively, like the login endpoint.
 */
export async function resolveUserByName(db: Db, name: string) {
    const user = await findUserByName(db, name);
    if (!user) {
        throw new ApiError(Codes.USER_NOT_FOUND, { message: "No user matches this name" });
    }
    return user;
}
