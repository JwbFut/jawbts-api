// Local dev bridge: speaks the Neon /sql HTTP protocol and forwards queries
// to a plain PostgreSQL server (e.g. the local server from `npx prisma dev`),
// so the edge-safe PrismaNeonHttp adapter can be used against a local database.
//
// Usage:
//   npm run dev:bridge
//
// Env:
//   BRIDGE_TARGET  PostgreSQL URL to forward queries to (defaults to DATABASE_URL)
//   BRIDGE_PORT    port the bridge listens on (default 51220)

import "dotenv/config";
import { createServer } from "node:http";
import pg from "pg";

const PORT = Number(process.env.BRIDGE_PORT || 51220);
const TARGET = process.env.BRIDGE_TARGET || process.env.DATABASE_URL;

if (!TARGET) {
    console.error(
        "BRIDGE_TARGET (or DATABASE_URL) is required, " +
            "e.g. postgres://postgres:postgres@localhost:51214/template1",
    );
    process.exit(1);
}

// Neon returns timestamps rendered in UTC; force the session to UTC so the local
// database (e.g. `prisma dev`) does the same.
const target = new URL(TARGET);
target.searchParams.append("options", "-c timezone=UTC");

const pool = new pg.Pool({
    connectionString: target.toString(),
    // Neon's HTTP endpoint returns raw Postgres text values; disable pg's
    // type parsing so rows stay exactly as the server sent them.
    types: { getTypeParser: () => (value) => value },
});

// Prisma sends datetimes as ISO strings with a UTC offset (e.g.
// "2026-08-03T09:16:02.628+08:00"). Real PostgreSQL converts them using the
// session timezone, but the local `prisma dev` engine drops the offset and
// stores the wall-clock value as-is. Normalize such parameters to UTC
// wall-clock strings so local storage matches what Neon would store.
const DATETIME_WITH_OFFSET =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

function normalizeParam(value) {
    if (typeof value === "string" && DATETIME_WITH_OFFSET.test(value)) {
        const date = new Date(value);
        if (!Number.isNaN(date.getTime())) {
            return date.toISOString().replace("T", " ").replace("Z", "");
        }
    }
    return value;
}

async function runOne({ query, params }) {
    if (process.env.BRIDGE_DEBUG) {
        console.error("[bridge]", JSON.stringify({ query, params }));
    }
    try {
        const result = await pool.query({
            text: query,
            values: (params ?? []).map(normalizeParam),
            rowMode: "array",
        });
        return {
            rows: result.rows,
            fields: result.fields.map((f) => ({
                name: f.name,
                dataTypeID: f.dataTypeID,
            })),
            command: result.command,
            rowCount: result.rowCount,
        };
    } catch (error) {
        return {
            error: {
                message: error.message,
                code: error.code,
                severity: error.severity,
                detail: error.detail,
                hint: error.hint,
                position: error.position ? Number(error.position) : undefined,
                where: error.where,
                schema: error.schema,
                table: error.table,
                column: error.column,
                constraint: error.constraint,
            },
        };
    }
}

const server = createServer(async (req, res) => {
    if (req.method !== "POST") {
        res.writeHead(405).end();
        return;
    }
    let body = "";
    for await (const chunk of req) {
        body += chunk;
    }
    let payload;
    try {
        payload = JSON.parse(body);
    } catch {
        res
            .writeHead(400, { "content-type": "application/json" })
            .end(JSON.stringify({ message: "invalid JSON body" }));
        return;
    }
    const batch = Array.isArray(payload.queries);
    const queries = batch ? payload.queries : [payload];
    const results = [];
    for (const query of queries) {
        const result = await runOne(query);
        if (result.error) {
            res
                .writeHead(400, { "content-type": "application/json" })
                .end(JSON.stringify(result.error));
            return;
        }
        results.push(result);
    }
    const response = batch ? { results } : results[0];
    res
        .writeHead(200, { "content-type": "application/json" })
        .end(JSON.stringify(response));
});

server.listen(PORT, "127.0.0.1", () => {
    console.log(
        `Neon HTTP bridge listening on http://127.0.0.1:${PORT}/sql -> ${TARGET}`,
    );
});
