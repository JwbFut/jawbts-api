import type { NextConfig } from "next";
import { BUILD_HASH, BUILD_HASH_HEADER } from "./src/lib/build-hash";
import { CORS_HEADERS } from "./src/lib/cors";

const nextConfig: NextConfig = {
    async headers() {
        return [
            {
                source: "/:path*",
                headers: [
                    ...Object.entries(CORS_HEADERS),
                    [BUILD_HASH_HEADER, BUILD_HASH] as const,
                ].map(([key, value]) => ({ key, value })),
            },
        ];
    },
};

export default nextConfig;
