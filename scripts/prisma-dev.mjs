#!/usr/bin/env node
/**
 * Runs `prisma dev` with a project-local XDG data directory so this project's
 * server cannot collide with a Prisma Dev server from another project (the
 * common "Port number 51213 belongs to another Prisma Dev server" error).
 *
 *   node scripts/prisma-dev.mjs dev --name jawbts --port 51213 ...
 *   node scripts/prisma-dev.mjs dev stop jawbts
 *   node scripts/prisma-dev.mjs dev ls
 */
import { spawn } from "node:child_process";
import path from "node:path";

const root = process.cwd();
process.env.XDG_DATA_HOME = path.join(root, ".prisma-dev-data");

const binary = path.join(
    root,
    "node_modules",
    ".bin",
    process.platform === "win32" ? "prisma.cmd" : "prisma",
);
const child = spawn(binary, process.argv.slice(2), {
    stdio: "inherit",
    env: process.env,
    shell: process.platform === "win32",
});

child.on("error", (error) => {
    console.error("Could not start Prisma Dev:", error.message);
    process.exit(1);
});
child.on("exit", (code, signal) => {
    if (signal) {
        process.kill(process.pid, signal);
        return;
    }
    process.exit(code ?? 1);
});
