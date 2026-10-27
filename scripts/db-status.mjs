#!/usr/bin/env node
/**
 * Reports whether the database behind .env is reachable and ready.
 *
 *   npm run db:status
 *
 * Exit code 0 when the database answers, 1 otherwise. Missing schema/test
 * account is reported separately (run `npm run db:seed`).
 */
import "dotenv/config";
import pg from "pg";

const url = process.env.DATABASE_URL?.trim();
const schema = process.env.DATABASE_SCHEMA?.trim() || "public";
const seedName = process.env.SEED_NAME?.trim() || "winsrewu";

function quoteIdentifier(identifier) {
    if (!/^[A-Za-z_][A-Za-z0-9_-]*$/.test(identifier)) {
        throw new Error(`Unsafe DATABASE_SCHEMA value: ${JSON.stringify(identifier)}`);
    }
    return `"${identifier}"`;
}

function safeUrl(raw) {
    try {
        const parsed = new URL(raw);
        const port = parsed.port ? `:${parsed.port}` : "";
        return `${parsed.protocol}//${parsed.hostname}${port}${parsed.pathname}`;
    } catch {
        return raw;
    }
}

if (!url) {
    console.error("[down] DATABASE_URL is not set");
    process.exit(1);
}
if (!/^postgres(ql)?:\/\//i.test(url)) {
    console.error(
        "[down] DATABASE_URL is not a postgres:// URL; this check uses the pg client " +
            "(the app's https:// Neon HTTP transport needs a different probe)",
    );
    process.exit(1);
}

const client = new pg.Client({ connectionString: url, connectionTimeoutMillis: 3000 });
try {
    await client.connect();
    const { rows: databaseRows } = await client.query("SELECT current_database() AS db");
    console.log(
        `[ok] database reachable: ${safeUrl(url)} (database "${databaseRows[0].db}")`,
    );

    const table = `${quoteIdentifier(schema)}."users"`;
    const { rows: tableRows } = await client.query("SELECT to_regclass($1) AS name", [table]);
    if (!tableRows[0].name) {
        console.log(`[missing] table ${schema}.users — run: npm run db:seed`);
    } else {
        console.log(`[ok] table ${schema}.users`);
        const { rows } = await client.query(
            `SELECT id, name, email, "githubId", permissions
               FROM ${table} WHERE name = $1`,
            [seedName],
        );
        if (rows.length === 0) {
            console.log(`[missing] test user "${seedName}" — run: npm run db:seed`);
        } else {
            const user = rows[0];
            console.log(
                `[ok] test user: id=${user.id} name=${user.name} ` +
                    `email=${
                        String(user.email).toLowerCase().endsWith("@placeholder.jawbts.org")
                            ? "[email change pending]"
                            : user.email
                    } githubId=${user.githubId}`,
            );
            console.log(
                `[ok] permissions: ${user.permissions.length > 0 ? user.permissions.join(", ") : "(none)"}`,
            );
        }
    }
} catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (error?.code === "42703") {
        console.error(
            `[outdated] schema is missing a column (${message}) — run: npm run db:seed`,
        );
    } else {
        console.error(`[down] ${safeUrl(url)} — ${message}`);
        if (/ECONNREFUSED|ENOTFOUND|EAI_AGAIN/.test(message)) {
            console.error("Start it with: npm run db:start");
        }
    }
    process.exitCode = 1;
} finally {
    await client.end().catch(() => {});
}
