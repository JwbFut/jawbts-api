import "dotenv/config";
import { defineConfig } from "prisma/config";

// Tables are isolated into their own PostgreSQL schema because the database
// may be shared. The CLI gets the schema via the `schema` URL parameter; the
// runtime adapter injects it through getConnectionInfo (see src/lib/prisma.ts).
const isGenerate = process.argv.includes("generate");
// `prisma generate` does not connect to a database. Do not make `npm ci`
// depend on deployment secrets; db push/migrate still require real values.
const dbSchema = process.env.DATABASE_SCHEMA?.trim() || (isGenerate ? "public" : "");
if (!dbSchema) {
    throw new Error("DATABASE_SCHEMA is required");
}
if (!/^[A-Za-z_][A-Za-z0-9_-]*$/.test(dbSchema)) {
    throw new Error("DATABASE_SCHEMA must be a valid PostgreSQL identifier");
}
const schema = dbSchema;
const databaseUrl =
    process.env.DATABASE_URL?.trim() ||
    (isGenerate ? "postgresql://localhost:5432/postgres" : "");
if (!databaseUrl) {
    throw new Error("DATABASE_URL is required");
}

function withSchema(url: string | undefined): string | undefined {
    if (!url) {
        return url;
    }
    const separator = url.includes("?") ? "&" : "?";
    return `${url}${separator}schema=${encodeURIComponent(schema)}`;
}

export default defineConfig({
    schema: "prisma/schema.prisma",
    datasource: {
        url: withSchema(databaseUrl),
        shadowDatabaseUrl: withSchema(process.env.SHADOW_DATABASE_URL),
    },
});
