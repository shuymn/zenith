import { describe, expect, it } from "vitest";

declare global {
  interface ImportMeta {
    glob<T>(patterns: string | string[], options: { query: string; import: string; eager: true }): Record<string, T>;
  }
}

// Non-test sources of packages/core. test-support.ts holds helpers used only by tests.
const sources = import.meta.glob<string>(["./**/*.ts", "!./**/*.test.ts", "!./test-support.ts"], {
  query: "?raw",
  import: "default",
  eager: true,
});

// `import ... from "..."`, `export ... from "..."`, `import "..."` and `import("...")`.
const IMPORT =
  /(?:^|\n)\s*(?:import|export)\s[^'"`;]*?\bfrom\s*['"]([^'"]+)['"]|(?:^|\n)\s*import\s*['"]([^'"]+)['"]|\bimport\(\s*['"]([^'"]+)['"]\s*\)/g;

// EV-7: core is pure and depends on @noble only. Every other specifier is refused, `cloudflare:*` and nostr-tools
// included (nostr-tools' verifyEvent caches its result on the object, so it is a test-only cross-check).
function isAllowedImport(specifier: string): boolean {
  return specifier.startsWith("./") || specifier.startsWith("../") || specifier.startsWith("@noble/");
}

const packageJson = import.meta.glob<string>("../package.json", { query: "?raw", import: "default", eager: true })[
  "../package.json"
];

// EV-2: the id is computed by serializeEvent, never with JSON.stringify. Files listed here may use it for other purposes.
const JSON_STRINGIFY_ALLOWED: Record<string, string> = {
  "./canonical.ts": "the canonical stored JSON of an already verified event (ST-7), not an id",
};
const JSON_STRINGIFY = /\bJSON\s*(?:\.\s*stringify\b|\[\s*['"`]stringify['"`]\s*\])/;

function stripComments(source: string): string {
  return source.replaceAll(/\/\*[\s\S]*?\*\//g, "").replaceAll(/(^|[^:\\])\/\/.*$/gm, "$1");
}

function violations(files: Record<string, string>): string[] {
  const found: string[] = [];
  for (const [file, raw] of Object.entries(files)) {
    const source = stripComments(raw);
    for (const match of source.matchAll(IMPORT)) {
      const specifier = match[1] ?? match[2] ?? match[3] ?? "";
      if (!isAllowedImport(specifier)) found.push(`${file}: imports ${specifier}`);
    }
    if (JSON_STRINGIFY.test(source) && JSON_STRINGIFY_ALLOWED[file] === undefined) {
      found.push(`${file}: uses JSON.stringify`);
    }
  }
  return found;
}

describe("source analysis of packages/core", () => {
  it("sees the source tree without test files", () => {
    expect(Object.keys(sources)).toEqual(expect.arrayContaining(["./event.ts", "./model.ts", "./index.ts"]));
    expect(Object.keys(sources).filter((file) => file.endsWith(".test.ts") || file === "./test-support.ts")).toEqual(
      [],
    );
  });

  it("EV-7, EV-2: has no forbidden import and no JSON.stringify outside the allowlist", () => {
    expect(violations(sources)).toEqual([]);
  });

  it("EV-7: declares only @noble packages as runtime dependencies", () => {
    const manifest: unknown = JSON.parse(packageJson ?? "null");
    const dependencies =
      typeof manifest === "object" && manifest !== null && "dependencies" in manifest
        ? manifest.dependencies
        : undefined;
    expect(Object.keys(dependencies ?? {}).toSorted()).toEqual(["@noble/curves", "@noble/hashes"]);
  });

  it("keeps the allowlist pointing at existing files", () => {
    expect(Object.keys(sources)).toEqual(expect.arrayContaining(Object.keys(JSON_STRINGIFY_ALLOWED)));
  });

  it("detects each violation", () => {
    expect(
      violations({
        "./a.ts": 'import { verifyEvent } from "nostr-tools";',
        "./b.ts": "import type { Event } from 'nostr-tools/pure'",
        "./c.ts": 'const { DurableObject } = await import("cloudflare:workers")',
        "./d.ts": 'export { env } from "cloudflare:workers";',
        "./e.ts": 'import "cloudflare:sockets";',
        "./f.ts": "const id = sha256(JSON.stringify([0, pubkey]))",
        "./g.ts": "const s = JSON.stringify; s(x)",
        "./h.ts": 'const s = JSON["stringify"](x)',
        "./i.ts": "// JSON.stringify(x) and nostr-tools in a comment\n/* import 'cloudflare:x' */\nconst u = 'wss://a'",
        "./canonical.ts": "return JSON.stringify(event)",
        "./j.ts": 'import * as fc from "fast-check"',
        "./k.ts": 'import { readFile } from "node:fs/promises"',
        "./l.ts": 'export { x } from "@noblex/curves"',
        "./m.ts": 'const m = await import("hono")',
        "./n.ts":
          'import { schnorr } from "@noble/curves/secp256k1.js"\nimport { x } from "../limits.ts"\nexport * from "./kind.ts"',
      }),
    ).toEqual([
      "./a.ts: imports nostr-tools",
      "./b.ts: imports nostr-tools/pure",
      "./c.ts: imports cloudflare:workers",
      "./d.ts: imports cloudflare:workers",
      "./e.ts: imports cloudflare:sockets",
      "./f.ts: uses JSON.stringify",
      "./g.ts: uses JSON.stringify",
      "./h.ts: uses JSON.stringify",
      "./j.ts: imports fast-check",
      "./k.ts: imports node:fs/promises",
      "./l.ts: imports @noblex/curves",
      "./m.ts: imports hono",
    ]);
  });
});
