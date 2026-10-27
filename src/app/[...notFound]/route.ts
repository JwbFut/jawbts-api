import { api, corsPreflight } from "@/lib/api";
import { Codes } from "@/lib/codes";
import { fail } from "@/lib/response";

export const OPTIONS = corsPreflight;

// Catch-all: any path that matches no other route returns the unified
// 404 envelope instead of Next.js' default HTML page.
const notFound = api(async () => fail(Codes.NOT_FOUND));

export const GET = notFound;
export const POST = notFound;
export const PUT = notFound;
export const PATCH = notFound;
export const DELETE = notFound;
export const HEAD = notFound;
