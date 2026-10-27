import { NextRequest } from "next/server";

// Next's RequestInit rejects `signal: null` (allowed by the DOM RequestInit),
// so derive the exact init type from the NextRequest constructor instead of
// using the global RequestInit.
export type NextRequestInit = NonNullable<ConstructorParameters<typeof NextRequest>[1]>;

export function request(url: string, init?: NextRequestInit): NextRequest {
    return new NextRequest(url, init);
}
