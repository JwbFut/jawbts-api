// Enforces case-insensitive email uniqueness at the database level.
// Prisma cannot express a functional index in schema.prisma, so this runs after
// db push/migrate. Existing case-variant duplicates must be resolved first.
import "dotenv/config";
import pg from "pg";

const url = process.env.DATABASE_URL;
const schema = process.env.DATABASE_SCHEMA?.trim();

if (!url || !schema) {
    console.error("DATABASE_URL and DATABASE_SCHEMA are required");
    process.exit(1);
}
if (!/^[A-Za-z_][A-Za-z0-9_-]*$/.test(schema)) {
    console.error("DATABASE_SCHEMA must be a valid PostgreSQL identifier");
    process.exit(1);
}

const pool = new pg.Pool({ connectionString: url });
try {
    const duplicates = await pool.query(
        `SELECT lower("email") AS email, count(*)::int AS count
           FROM "${schema}"."users"
          GROUP BY 1
         HAVING count(*) > 1`,
    );
    if (duplicates.rowCount > 0) {
        console.error(
            "Case-insensitive duplicate emails block the unique index:",
            duplicates.rows,
        );
        process.exitCode = 1;
    } else {
        await pool.query(
            `CREATE UNIQUE INDEX IF NOT EXISTS "users_email_lower_key"
               ON "${schema}"."users" (lower("email"))`,
        );
        console.log(`Ensured lower(email) unique index on "${schema}"."users"`);
    }
} catch (error) {
    console.error("Could not ensure email uniqueness index:", error.message);
    process.exitCode = 1;
} finally {
    await pool.end();
}
