import { readdirSync, writeFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import type { Plugin } from "vite";
import { defineConfig } from "vitest/config";

const API_TARGET = process.env.ORACLE_HCM_API_ORIGIN ?? "http://127.0.0.1:8000";

const API_PATHS = ["/auth", "/tasks", "/approvals", "/events", "/metrics", "/health"];

const root = fileURLToPath(new URL(".", import.meta.url));

function shellFiles(directory: string): string[] {
  const files: string[] = [];
  const walk = (current: string): void => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const full = join(current, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else {
        files.push("/" + relative(directory, full).split(sep).join("/"));
      }
    }
  };
  walk(directory);
  return files.sort();
}

/** Writes the list of the files of the app shell, so the worker can cache them. */
function precacheManifest(): Plugin {
  return {
    name: "oracle-hcm-precache",
    apply: "build",
    closeBundle() {
      const dist = join(root, "dist");
      const files = shellFiles(dist);
      writeFileSync(
        join(dist, "precache.json"),
        JSON.stringify({ files }, null, 2),
        "utf8",
      );
    },
  };
}

export default defineConfig({
  plugins: [react(), precacheManifest()],
  build: {
    outDir: "dist",
    target: "es2022",
    sourcemap: false,
  },
  server: {
    port: 5173,
    strictPort: false,
    proxy: Object.fromEntries(
      API_PATHS.map((path) => [path, { target: API_TARGET, changeOrigin: false }]),
    ),
  },
  test: {
    environment: "jsdom",
    globals: false,
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    restoreMocks: true,
  },
});
