import { api, corsPreflight } from "@/lib/api";
import { ok } from "@/lib/response";

export const OPTIONS = corsPreflight;

export const GET = api(async () => {
    return ok({
        name: "jawbts-api",
    });
});
