#!/usr/bin/env node
/**
 * Emergency operator recovery for a corrupt/legacy email placeholder.
 *
 *   npm run db:reset-email -- <username> <email>
 *
 * This bypasses the confirmation flow: it sets a real address immediately and
 * clears all pending email-change state. Only use it when the stored
 * placeholder cannot be decoded and the normal PATCH flow returns 10015.
 */
import "dotenv/config";
import pg from "pg";

const [name, email] = process.argv.slice(2);

function quoteIdentifier(identifier) {
    if (!/^[A-Za-z_][A-Za-z0-9_-]*$/.test(identifier)) {
        throw new Error(`Unsafe DATABASE_SCHEMA value: ${JSON.stringify(identifier)}`);
    }
    return `"${identifier}"`;
}

if (!name || !email) {
    console.error("Usage: npm run db:reset-email -- <username> <email>");
    process.exit(1);
}
if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    console.error("A valid email address is required.");
    process.exit(1);
}
if (email.toLowerCase().endsWith("@placeholder.jawbts.org")) {
    console.error("The placeholder.jawbts.org domain is reserved.");
    process.exit(1);
}

const url = process.env.DATABASE_URL?.trim();
const schema = process.env.DATABASE_SCHEMA?.trim() || "public";
if (!url) {
    console.error("DATABASE_URL is not set.");
    process.exit(1);
}

const client = new pg.Client({ connectionString: url });
await client.connect();
try {
    const table = `${quoteIdentifier(schema)}."users"`;
    const { rows } = await client.query(
        `UPDATE ${table}
            SET email = $1,
                "emailChangeTokenHash" = NULL,
                "emailChangeExpiresAt" = NULL,
                "emailChangeLastSentAt" = NULL,
                "updatedAt" = NOW()
          WHERE name = $2
          RETURNING id, name, email`,
        [email, name],
    );
    if (rows.length === 0) {
        console.error(`No user named ${JSON.stringify(name)}.`);
        process.exitCode = 1;
    } else {
        console.log(`Reset email for ${rows[0].name} (id=${rows[0].id}) to ${rows[0].email}`);
    }
} catch (error) {
    console.error(`Reset failed: ${error.message}`);
    process.exitCode = 1;
} finally {
    await client.end();
}
