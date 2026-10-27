import { afterEach, describe, expect, it, vi } from "vitest";
import { request } from "@/test/request";
import { GET, textList, textListSquared } from "./route";

function get() {
    return GET(request("http://localhost/text"), {});
}

async function body(res: Response) {
    return res.json();
}

describe("GET /text", () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    it("returns the success envelope", async () => {
        const res = await get();
        expect(res.status).toBe(200);
        const json = await body(res);
        expect(json.success).toBe(true);
        expect(json.code).toBe(200);
        expect(json.message).toBe("OK");
    });

    it("serves a pair from textList with empty context in normal mode", async () => {
        vi.spyOn(Math, "random")
            .mockReturnValueOnce(0.1) // useMultisentence = false
            .mockReturnValueOnce(0); // pair start 0
        const { data } = await body(await get());
        expect(data.context).toEqual([]);
        expect(data.a).toBe(textList[0]);
        expect(data.b).toBe(textList[1]);
    });

    it("serves a pair with the whole group as context in multi mode", async () => {
        vi.spyOn(Math, "random")
            .mockReturnValueOnce(0.95) // useMultisentence = true
            .mockReturnValueOnce(0) // group index 0
            .mockReturnValueOnce(0); // pair start 0
        const { data } = await body(await get());
        const group = textListSquared[0];
        expect(data.context).toEqual(group);
        expect(data.a).toBe(group[0]);
        expect(data.b).toBe(group[1]);
    });

    it("always returns a valid pair with a consistent context", async () => {
        // `a` may repeat in the lists, so assert (a, b) is one of the fixed
        // pairs instead of locating `a` with indexOf.
        const isPair = (list: string[], a: string, b: string) =>
            list.some((v, j) => j % 2 === 0 && v === a && list[j + 1] === b);
        for (let i = 0; i < 200; i++) {
            const { data } = await body(await get());
            expect(typeof data.a).toBe("string");
            expect(typeof data.b).toBe("string");
            expect(Array.isArray(data.context)).toBe(true);
            if (data.context.length > 0) {
                // multi mode: context is one of the groups, (a, b) a pair in it
                expect(textListSquared).toContainEqual(data.context);
                expect(isPair(data.context, data.a, data.b)).toBe(true);
            } else {
                // normal mode: (a, b) is a pair from textList
                expect(isPair(textList, data.a, data.b)).toBe(true);
            }
        }
    });
});
