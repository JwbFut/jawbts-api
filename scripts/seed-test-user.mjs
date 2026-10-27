#!/usr/bin/env node
/**
 * Seeds the manual testing account.
 *
 *   npm run db:seed
 *
 * The npm script pushes the Prisma schema first, then this script upserts the
 * account. It only touches the database; `npm test` runs fully mocked and is
 * unaffected.
 *
 * Overridable: SEED_NAME, SEED_EMAIL, SEED_GITHUB_ID.
 */
import "dotenv/config";
import { createRequire } from "node:module";
import pg from "pg";

const require = createRequire(import.meta.url);
const PERMISSION_CATALOG = require("../src/lib/permissions.json");

const DEFAULT_NAME = "winsrewu";
const DEFAULT_EMAIL = "winsrewu@jawbts.org";
// winsrewu's real GitHub numeric id, so the OAuth identity check passes when
// logging in through GitHub. Override for a different test account.
const DEFAULT_GITHUB_ID = "78122384";
// Shared with src/lib/permissions.ts (a test guards the two catalogs).
const KNOWN_PERMISSIONS = new Set(PERMISSION_CATALOG.user);
const DEFAULT_PERMISSIONS = PERMISSION_CATALOG.user;

const name = process.env.SEED_NAME?.trim() || DEFAULT_NAME;
const email = (process.env.SEED_EMAIL?.trim() || DEFAULT_EMAIL).toLowerCase();
const githubId = process.env.SEED_GITHUB_ID?.trim() || DEFAULT_GITHUB_ID;
if (email.toLowerCase().endsWith("@placeholder.jawbts.org")) {
    throw new Error("SEED_EMAIL cannot use the reserved placeholder.jawbts.org domain");
}
const permissions = [
    ...new Set(
        (process.env.SEED_PERMISSIONS?.trim()
            ? process.env.SEED_PERMISSIONS.split(",")
            : DEFAULT_PERMISSIONS
        )
            .map((permission) => permission.trim())
            .filter(Boolean),
    ),
];
const schema = (process.env.DATABASE_SCHEMA?.trim() || "public");
const connectionString = process.env.DATABASE_URL?.trim();

function quoteIdentifier(identifier) {
    if (!/^[A-Za-z_][A-Za-z0-9_-]*$/.test(identifier)) {
        throw new Error(`Unsafe DATABASE_SCHEMA value: ${JSON.stringify(identifier)}`);
    }
    return `"${identifier}"`;
}

async function main() {
    if (!connectionString) {
        throw new Error("DATABASE_URL is not set");
    }
    if (!/^postgres(ql)?:\/\//i.test(connectionString)) {
        throw new Error(
            "DATABASE_URL must be a postgres:// or postgresql:// URL " +
                "(a Neon https:// URL cannot be used by the pg client)",
        );
    }
    const unknown = permissions.filter((permission) => !KNOWN_PERMISSIONS.has(permission));
    if (unknown.length > 0) {
        throw new Error(
            `Unknown permission(s): ${unknown.join(", ")}. ` +
                `Known: ${[...KNOWN_PERMISSIONS].join(", ")}`,
        );
    }

    const client = new pg.Client({ connectionString });
    await client.connect();
    try {
        const table = `${quoteIdentifier(schema)}."users"`;
        const { rows } = await client.query(
            `INSERT INTO ${table}
               (email, name, "githubId", permissions, "createdAt", "updatedAt")
             VALUES ($1, $2, $3, $4::text[], NOW(), NOW())
             ON CONFLICT (name) DO UPDATE
               SET email = EXCLUDED.email,
                   "githubId" = EXCLUDED."githubId",
                   permissions = EXCLUDED.permissions,
                   "emailChangeTokenHash" = NULL,
                   "emailChangeExpiresAt" = NULL,
                   "emailChangeLastSentAt" = NULL,
                   "updatedAt" = NOW()
             RETURNING id, name, email, "githubId", permissions`,
            [email, name, githubId, permissions],
        );
        const user = rows[0];
        console.log("Test account ready:");
        console.log(`  id:          ${user.id}`);
        console.log(`  name:        ${user.name}`);
        console.log(`  email:       ${user.email}`);
        console.log(`  githubId:    ${user.githubId}`);
        console.log(`  permissions: ${user.permissions.join(", ") || "(none)"}`);
        console.log("");
        console.log(`Log in with the GitHub username "${user.name}".`);
    } finally {
        await client.end();
    }
}

try {
    await main();
} catch (error) {
    const code = error?.code;
    if (code === "23505") {
        console.error(
            `Seeding failed: email ${email} or name ${name} is already used by a different account.`,
        );
    } else if (code === "42P01") {
        console.error("Seeding failed: the users table does not exist. Run `npm run db:push` first.");
    } else {
        const message = error instanceof Error ? error.message : String(error);
        console.error("Seeding failed:", message);
        if (/ECONNREFUSED|ENOTFOUND|EAI_AGAIN/.test(message)) {
            console.error(
                "Is the database running? Start it first (e.g. `npx prisma dev` + the bridge).",
            );
        }
    }
    process.exitCode = 1;
}
