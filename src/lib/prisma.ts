import { PrismaClient } from "@/generated/prisma/client";

let client: PrismaClient | undefined;
let clientPromise: Promise<PrismaClient> | undefined;
let adapterSupportsTransactions = true;

/** Bound Neon calls so a stuck connection cannot consume Vercel's full timeout. */
const DB_CONNECTION_TIMEOUT_MS = 60_000;
const DB_QUERY_TIMEOUT_MS = 60_000;
const SCHEMA_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_-]*$/;

function resolveSchema(): string | undefined {
    const raw = process.env.DATABASE_SCHEMA?.trim();
    if (!raw) {
        if (process.env.NODE_ENV === "production") {
            throw new Error("DATABASE_SCHEMA is required in production");
        }
        return undefined;
    }
    if (!SCHEMA_IDENTIFIER.test(raw)) {
        throw new Error("DATABASE_SCHEMA must be a valid PostgreSQL identifier");
    }
    return raw;
}

/**
 * The HTTP adapter does not report a schema to Prisma (it would default to
 * "public"), so wrap the factory and inject the schema via getConnectionInfo.
 */
function withSchema<F extends { provider: string; connect: () => Promise<A> }, A>(
    factory: F,
    schema?: string,
): F {
    if (!schema) {
        return factory;
    }
    const wrapped = {
        provider: factory.provider,
        adapterName: (factory as { adapterName?: string }).adapterName,
        connect: async (): Promise<A> => {
            const adapter = await factory.connect();
            const record = adapter as Record<string, unknown>;
            const original =
                typeof record.getConnectionInfo === "function"
                    ? (record.getConnectionInfo as () => Record<string, unknown>).bind(
                        adapter,
                    )
                    : undefined;
            record.getConnectionInfo = () => ({
                supportsRelationJoins: true,
                ...(original ? original() : {}),
                schemaName: schema,
            });
            return adapter;
        },
    };
    return wrapped as unknown as F;
}

async function createAdapter(connectionString: string) {
    const schema = resolveSchema();
    const { PrismaNeon, PrismaNeonHttp } = await import("@prisma/adapter-neon");
    // http(s):// Neon URL -> stateless HTTP queries (fetch only, no transactions).
    if (connectionString.startsWith("http")) {
        adapterSupportsTransactions = false;
        const neon = await import("@neondatabase/serverless");
        neon.neonConfig.fetchFunction = (
            input: Parameters<typeof fetch>[0],
            init?: Parameters<typeof fetch>[1],
        ) => fetch(input, { ...init, signal: AbortSignal.timeout(DB_QUERY_TIMEOUT_MS) });
        return withSchema(new PrismaNeonHttp(connectionString, {}), schema);
    }
    // NEON_HTTP_ENDPOINT set -> send the Neon HTTP protocol to a custom endpoint,
    // e.g. the local dev bridge in scripts/neon-http-bridge.mjs. A localhost
    // bridge accidentally present in production must not win over DATABASE_URL.
    const rawHttpEndpoint = process.env.NEON_HTTP_ENDPOINT?.trim();
    const isLocalBridge =
        Boolean(rawHttpEndpoint) &&
        /^https?:\/\/(127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\])(?::|\/|$)/i.test(
            rawHttpEndpoint!,
        );
    const httpEndpoint =
        rawHttpEndpoint &&
        !(process.env.NODE_ENV === "production" && isLocalBridge)
            ? rawHttpEndpoint
            : undefined;
    if (process.env.NODE_ENV === "production" && isLocalBridge) {
        console.warn(
            "Ignoring local NEON_HTTP_ENDPOINT in production; use DATABASE_URL transport",
        );
    }
    if (httpEndpoint) {
        adapterSupportsTransactions = false;
        const neon = await import("@neondatabase/serverless");
        neon.neonConfig.fetchEndpoint = httpEndpoint;
        neon.neonConfig.fetchFunction = (
            input: Parameters<typeof fetch>[0],
            init?: Parameters<typeof fetch>[1],
        ) => fetch(input, { ...init, signal: AbortSignal.timeout(DB_QUERY_TIMEOUT_MS) });
        return withSchema(new PrismaNeonHttp(connectionString, {}), schema);
    }
    // Default: Neon WebSocket pool. The Neon driver accepts the same timeout
    // knobs as node-postgres; without them a stalled socket can hang a route
    // until the platform kills it.
    return new PrismaNeon(
        {
            connectionString,
            connectionTimeoutMillis: DB_CONNECTION_TIMEOUT_MS,
            query_timeout: DB_QUERY_TIMEOUT_MS,
            statement_timeout: DB_QUERY_TIMEOUT_MS,
        },
        schema ? { schema } : undefined,
    );
}

/**
 * Whether the active adapter can run transactions. The WebSocket pool can;
 * the Neon HTTP transport is stateless and its startTransaction rejects.
 * Only meaningful after getPrisma() has resolved once.
 */
export function supportsTransactions(): boolean {
    return adapterSupportsTransactions;
}

export async function getPrisma(): Promise<PrismaClient> {
    if (client) {
        return client;
    }
    if (!clientPromise) {
        // Cache the promise, not only the resolved client: concurrent
        // cold-start requests must share one adapter/pool.
        clientPromise = (async () => {
            const connectionString = process.env.DATABASE_URL;
            if (!connectionString) {
                throw new Error("DATABASE_URL is not set");
            }
            const created = new PrismaClient({
                adapter: await createAdapter(connectionString),
            });
            client = created;
            return created;
        })().catch((error: unknown) => {
            clientPromise = undefined;
            throw error;
        });
    }
    return clientPromise;
}
