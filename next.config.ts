import type { NextConfig } from "next";
import { CORS_HEADERS } from "./src/lib/cors";

const nextConfig: NextConfig = {
    async headers() {
        return [
            {
                source: "/:path*",
                headers: Object.entries(CORS_HEADERS).map(([key, value]) => ({
                    key,
                    value,
                })),
            },
        ];
    },
};

export default nextConfig;
