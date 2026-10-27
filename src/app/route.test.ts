import { describe, expect, it } from "vitest";
import { request } from "@/test/request";
import { GET } from "./route";

describe("GET /", () => {
    it("returns the service name without a version", async () => {
        const res = await GET(request("http://localhost/"), {});
        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.data).toEqual({ name: "jawbts-api" });
    });
});
