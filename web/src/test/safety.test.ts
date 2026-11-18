import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const WEB_ROOT = path.resolve(import.meta.dirname, "..", "..");

interface SourceFile {
  file: string;
  text: string;
}

function collect(dir: string, skip: (name: string) => boolean): SourceFile[] {
  const found: SourceFile[] = [];
  for (const entry of readdirSync(dir)) {
    if (skip(entry)) {
      continue;
    }
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) {
      found.push(...collect(full, skip));
      continue;
    }
    found.push({ file: path.relative(WEB_ROOT, full), text: readFileSync(full, "utf8") });
  }
  return found;
}

const sources = [
  ...collect(path.join(WEB_ROOT, "src"), (name) => name === "test"),
  ...collect(path.join(WEB_ROOT, "public"), () => false),
  ...collect(path.join(WEB_ROOT, "sw"), () => false),
  { file: "index.html", text: readFileSync(path.join(WEB_ROOT, "index.html"), "utf8") },
];

const FORBIDDEN: { label: string; pattern: RegExp }[] = [
  { label: "dangerouslySetInnerHTML", pattern: /dangerouslySetInnerHTML/ },
  { label: "innerHTML", pattern: /\.innerHTML\b/ },
  { label: "outerHTML", pattern: /\.outerHTML\b/ },
  { label: "insertAdjacentHTML", pattern: /insertAdjacentHTML/ },
  { label: "document.write", pattern: /document\.write\b/ },
  { label: "eval", pattern: /\beval\s*\(/ },
  { label: "new Function", pattern: /new\s+Function\s*\(/ },
  { label: "an inline style attribute", pattern: /style=\{\{/ },
];

const SECRETS: { label: string; pattern: RegExp }[] = [
  { label: "an api key", pattern: /\bsk-[A-Za-z0-9_-]{12,}/ },
  { label: "a private key", pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { label: "a bearer token", pattern: /Bearer\s+[A-Za-z0-9._-]{16,}/ },
  { label: "a password in clear", pattern: /["'](?:password|passwd|secret)["']\s*[:=]\s*["'][^"']{6,}["']/i },
];

describe("the sources of the console", () => {
  it("has something to look at", () => {
    expect(sources.length).toBeGreaterThan(20);
  });

  for (const { label, pattern } of FORBIDDEN) {
    it(`never uses ${label}`, () => {
      const offenders = sources
        .filter((source) => pattern.test(source.text))
        .map((source) => source.file);
      expect(offenders).toEqual([]);
    });
  }

  for (const { label, pattern } of SECRETS) {
    it(`holds no ${label}`, () => {
      const offenders = sources
        .filter((source) => pattern.test(source.text))
        .map((source) => source.file);
      expect(offenders).toEqual([]);
    });
  }

  it("keeps the script of the page in an external file", () => {
    const inline = /<script(?![^>]*\bsrc=)[^>]*>[\s\S]*?\S[\s\S]*?<\/script>/.exec(
      sources.find((source) => source.file === "index.html")?.text ?? "",
    );
    expect(inline).toBeNull();
  });

  it("keeps the handlers of the page out of the markup", () => {
    const html = sources.find((source) => source.file === "index.html")?.text ?? "";
    expect(/\son[a-z]+=/i.test(html)).toBe(false);
  });
});

describe("the service worker", () => {
  const worker = sources.find((source) => source.file === path.join("sw", "sw.js"))?.text ?? "";

  it("leaves the api out of the cache", () => {
    for (const prefix of ["/auth", "/tasks", "/approvals", "/events", "/metrics", "/health"]) {
      expect(worker).toContain(`"${prefix}"`);
    }
    expect(worker).toContain("API_PREFIXES.some");
  });

  it("never stores a request that carries the session", () => {
    expect(worker).toContain('request.method !== "GET"');
    expect(worker).not.toMatch(/cache\.put\(/);
  });
});
