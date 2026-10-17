import { describe, expect, it } from "vitest";

declare global {
  interface ImportMeta {
    glob<T>(patterns: string | string[], options: { query: string; import: string; eager: true }): Record<string, T>;
  }
}

// Non-test sources of packages/relay. test-support.ts holds helpers used only by tests.
const sources = import.meta.glob<string>(["./**/*.ts", "!./**/*.test.ts", "!./test-support.ts"], {
  query: "?raw",
  import: "default",
  eager: true,
});

/**
 * RES-2: the query argument of an `exec(` call is allowed only in these shapes. A string literal or a template literal
 * without substitutions is allowed anywhere; anything else only where listed, per file. Everything not allowed, such
 * as a template literal with `${`, string concatenation or a variable, is a violation.
 */
const EXEC_ARGUMENT_ALLOWED: Record<string, Record<string, string>> = {
  "./store.ts": { "query.text": "the text of a Sql built by the sql tag in sql.ts, whose values are all bound" },
};
const PLAIN_LITERAL = /^(?:"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\$]|\\.|\$(?!\{))*`)$/s;
// `exec(`, also with type arguments: `exec<Row>(`.
const EXEC_CALL = /\bexec\s*(?:<[^()]*>\s*)?\(/g;

/** Files that may read the SQL capability of a storage object (`.sql`). */
const SQL_CAPABILITY_ALLOWED: Record<string, string> = {
  "./store.ts": "held in the #storage field of EventStore and used by #run only",
};
const SQL_CAPABILITY = /\.\s*sql\b/;

/**
 * Forbidden APIs, each allowed only in the files listed with the reason. Everything not listed is a violation.
 * RES-3: connections use the hibernation API (`ctx.acceptWebSocket`, never a WebSocket's `.accept()`), and the DO keeps
 * no resident timer. DATA-1: only log.ts writes to the console, with fields from closed sets. EV-1: a received event is
 * verified from its text with verifyEvent; verifyEventObject, which skips the size limit, is for restores only.
 */
const FORBIDDEN_APIS: readonly { label: string; pattern: RegExp; allowed: Record<string, string> }[] = [
  { label: "calls .accept()", pattern: /\.\s*accept\s*\(/, allowed: {} },
  { label: "uses setInterval", pattern: /\bsetInterval\b/, allowed: {} },
  {
    label: "uses console",
    pattern: /\bconsole\b/,
    allowed: { "./log.ts": "logEvent, whose fields are typed by closed sets" },
  },
  {
    label: "brands an AuthorizedCommand",
    pattern: /\bas\s+AuthorizedCommand\b/,
    allowed: { "./admin.ts": "authorizeAdminRequest, after the owner's NIP-98 signature is verified (OPS-1)" },
  },
  {
    label: "uses the backup bucket",
    pattern: /\bBACKUPS\b/,
    allowed: {
      "./env.d.ts": "the binding's declaration",
      "./vault.ts": "Vault.backup and the restore of Vault.admin (DATA-5, ST-6)",
    },
  },
  {
    label: "uses verifyEventObject",
    pattern: /\bverifyEventObject\b/,
    allowed: { "./store.ts": "EventStore.restore, which checks backup events without the received limits (ST-6)" },
  },
];

// `import ... from "..."`, `export ... from "..."`, `import "..."` and `import("...")`.
const IMPORT =
  /(?:^|\n)\s*(?:import|export)\s[^'"`;]*?\bfrom\s*['"]([^'"]+)['"]|(?:^|\n)\s*import\s*['"]([^'"]+)['"]|\bimport\(\s*['"]([^'"]+)['"]\s*\)/g;

/** OPS-3: relay depends on core and the platform only, never on another package of this repository. */
function isAllowedImport(specifier: string): boolean {
  return (
    specifier.startsWith("./") ||
    specifier.startsWith("../") ||
    specifier === "@zenith/core" ||
    specifier === "cloudflare:workers"
  );
}

/**
 * DATA-2: the Worker's configuration holds no secret. Env declares exactly these bindings, the configuration files
 * set no other variable and no secret, and nothing names a secret key.
 */
const ENV_BINDINGS = ["BACKUPS", "OWNER_PUBKEY", "RELAY_URL", "VAULT"];
const DEPLOY_VARS = ["OWNER_PUBKEY", "RELAY_URL"];
const configFiles = import.meta.glob<string>(
  [
    "../wrangler.jsonc",
    "../wrangler.deploy.example.jsonc",
    "../.dev.vars.example",
    "../scripts/*.mjs",
    "../scripts/*.ts",
  ],
  { query: "?raw", import: "default", eager: true },
);

/** The member names of `interface Env` in env.d.ts. */
function envBindings(source: string): string[] {
  const body = /interface Env \{([\s\S]*?)\n {2}\}/.exec(stripComments(source))?.[1] ?? "";
  return [...body.matchAll(/^\s*(\w+)\??:/gm)].map((match) => match[1] ?? "").toSorted();
}

/** The keys of a JSONC object's `vars`. */
function jsoncVars(text: string): string[] | undefined {
  const value: unknown = JSON.parse(stripComments(text).replaceAll(/,(\s*[\]}])/g, "$1"));
  if (typeof value !== "object" || value === null || !("vars" in value)) return undefined;
  return Object.keys(value.vars ?? {}).toSorted();
}

/** A bech32 secret key, or a variable or binding whose name says it holds one. */
const SECRET_KEY = /\bnsec1[02-9ac-hj-np-z]{6,}|\b[A-Z_]*(?:SECRET|PRIVATE|NSEC)[A-Z_]*\b|"secrets"\s*:/;

const packageJson = import.meta.glob<string>("../package.json", { query: "?raw", import: "default", eager: true })[
  "../package.json"
];

function stripComments(source: string): string {
  return source.replaceAll(/\/\*[\s\S]*?\*\//g, "").replaceAll(/(^|[^:\\])\/\/.*$/gm, "$1");
}

/** The text of the first argument of a call whose `(` is at `open`, up to the top-level `,` or `)`. */
function firstArgument(source: string, open: number): string {
  let depth = 0;
  let quote: string | undefined;
  for (let i = open + 1; i < source.length; i++) {
    const char = source[i];
    if (quote !== undefined) {
      if (char === "\\") i++;
      else if (char === quote) quote = undefined;
      continue;
    }
    if (char === '"' || char === "'" || char === "`") quote = char;
    else if (char === "(" || char === "[" || char === "{") depth++;
    else if (char === ")" || char === "]" || char === "}") {
      if (depth === 0) return source.slice(open + 1, i).trim();
      depth--;
    } else if (char === "," && depth === 0) return source.slice(open + 1, i).trim();
  }
  return source.slice(open + 1).trim();
}

function violations(files: Record<string, string>): string[] {
  const found: string[] = [];
  for (const [file, raw] of Object.entries(files)) {
    const source = stripComments(raw);
    for (const match of source.matchAll(EXEC_CALL)) {
      const argument = firstArgument(source, match.index + match[0].length - 1);
      if (PLAIN_LITERAL.test(argument)) continue;
      if (EXEC_ARGUMENT_ALLOWED[file]?.[argument] !== undefined) continue;
      found.push(`${file}: exec(${argument.replaceAll(/\s+/g, " ")})`);
    }
    if (SQL_CAPABILITY.test(source) && SQL_CAPABILITY_ALLOWED[file] === undefined) {
      found.push(`${file}: reads .sql`);
    }
    for (const { label, pattern, allowed } of FORBIDDEN_APIS) {
      if (pattern.test(source) && allowed[file] === undefined) found.push(`${file}: ${label}`);
    }
    for (const match of source.matchAll(IMPORT)) {
      const specifier = match[1] ?? match[2] ?? match[3] ?? "";
      if (!isAllowedImport(specifier)) found.push(`${file}: imports ${specifier}`);
    }
  }
  return found;
}

describe("source analysis of packages/relay", () => {
  it("sees the source tree without test files", () => {
    expect(Object.keys(sources)).toEqual(
      expect.arrayContaining(["./store.ts", "./sql.ts", "./index.ts", "./vault.ts", "./log.ts"]),
    );
    expect(Object.keys(sources).filter((file) => file.endsWith(".test.ts") || file === "./test-support.ts")).toEqual(
      [],
    );
  });

  it("RES-2, RES-3, DATA-1, EV-1, OPS-3: has no forbidden SQL, API or import outside the allowlists", () => {
    expect(violations(sources)).toEqual([]);
  });

  it("OPS-3: declares only @zenith/core as a runtime dependency", () => {
    const manifest: unknown = JSON.parse(packageJson ?? "null");
    const dependencies =
      typeof manifest === "object" && manifest !== null && "dependencies" in manifest
        ? manifest.dependencies
        : undefined;
    expect(Object.keys(dependencies ?? {})).toEqual(["@zenith/core"]);
  });

  it("DATA-2: declares no binding beyond the vault, the backup bucket and two public variables", () => {
    expect(envBindings(sources["./env.d.ts"] ?? "")).toEqual(ENV_BINDINGS);
    expect(Object.keys(configFiles).toSorted()).toEqual([
      "../.dev.vars.example",
      "../scripts/deploy-config.ts",
      "../scripts/deploy.mjs",
      "../wrangler.deploy.example.jsonc",
      "../wrangler.jsonc",
    ]);
    // The public configuration sets no variable; the deployment file sets exactly these two.
    expect(jsoncVars(configFiles["../wrangler.jsonc"] ?? "")).toBeUndefined();
    expect(jsoncVars(configFiles["../wrangler.deploy.example.jsonc"] ?? "")).toEqual(DEPLOY_VARS);
    for (const [file, text] of Object.entries({ ...sources, ...configFiles })) {
      expect({ file, secret: SECRET_KEY.exec(stripComments(text))?.[0] }).toEqual({ file, secret: undefined });
    }
  });

  it("DATA-2: detects a secret key, a secret's name and another binding", () => {
    for (const text of [
      "nsec1qqqqqqqqqqqqqqqqq",
      "OWNER_SECRET_KEY=abc",
      "env.NOSTR_PRIVATE_KEY",
      '{ "secrets": { "required": ["X"] } }',
    ]) {
      expect({ text, found: SECRET_KEY.test(text) }).toEqual({ text, found: true });
    }
    expect(SECRET_KEY.test('{ "vars": { "OWNER_PUBKEY": "00", "RELAY_URL": "wss://a/" } }')).toBe(false);
    expect(envBindings("interface Env {\n    VAULT: X;\n    SIGNER_KEY: string;\n  }")).toEqual([
      "SIGNER_KEY",
      "VAULT",
    ]);
    expect(jsoncVars('{ // c\n "vars": { "B": 1, "A": 2, }, }')).toEqual(["A", "B"]);
  });

  it("keeps the allowlists pointing at existing files and allowed arguments in use", () => {
    for (const [file, allowed] of Object.entries(EXEC_ARGUMENT_ALLOWED)) {
      const source = stripComments(sources[file] ?? "");
      const used = [...source.matchAll(EXEC_CALL)].map((match) =>
        firstArgument(source, match.index + match[0].length - 1),
      );
      expect(used).toEqual(expect.arrayContaining(Object.keys(allowed)));
    }
    expect(Object.keys(sources)).toEqual(expect.arrayContaining(Object.keys(SQL_CAPABILITY_ALLOWED)));
    for (const { pattern, allowed } of FORBIDDEN_APIS) {
      for (const file of Object.keys(allowed)) expect(pattern.test(stripComments(sources[file] ?? ""))).toBe(true);
    }
  });

  it("detects each forbidden API and import", () => {
    expect(
      violations({
        "./a.ts": "server.accept();\nws . accept ( )",
        "./b.ts": "const timer = setInterval(tick, 1000);",
        "./c.ts": "console.log(event.content);",
        "./d.ts": "const { log } = console;",
        "./e.ts": "const result = verifyEventObject(JSON.parse(text));",
        "./f.ts": 'import { verifyEvent } from "nostr-tools";',
        "./g.ts": 'export { x } from "@zenith/blossom";\nconst m = await import("node:fs");',
        "./h.ts": 'import "cloudflare:sockets";',
        "./j.ts": "return { ok: true, command: parsed as AuthorizedCommand };",
        "./k.ts": "await this.env.BACKUPS.delete(key);",
        "./log.ts": "console.error(line);",
        "./store.ts": "verifyEventObject(value);",
        "./i.ts":
          '// server.accept(); console.log(x); setInterval(f)\nthis.ctx.acceptWebSocket(server);\nimport { a } from "@zenith/core";\nimport { b } from "./b.ts";',
      }),
    ).toEqual([
      "./a.ts: calls .accept()",
      "./b.ts: uses setInterval",
      "./c.ts: uses console",
      "./d.ts: uses console",
      "./e.ts: uses verifyEventObject",
      "./f.ts: imports nostr-tools",
      "./g.ts: imports @zenith/blossom",
      "./g.ts: imports node:fs",
      "./h.ts: imports cloudflare:sockets",
      "./j.ts: brands an AuthorizedCommand",
      "./k.ts: uses the backup bucket",
    ]);
  });

  it("detects each violation", () => {
    expect(
      violations({
        "./a.ts": "sql.exec(`SELECT * FROM events WHERE id = '${id}'`)",
        "./b.ts": 'this.sql.exec("SELECT * FROM events WHERE id = \'" + id + "\'")',
        "./c.ts": "storage.sql.exec(query)",
        "./d.ts": 'sql.exec(\n  "SELECT 1" +\n  "-- " + x,\n  y,\n)',
        "./e.ts": "sql.exec(query.text, ...query.params)",
        "./f.ts": "cursor = sql.exec(`SELECT ${columns} FROM events`)",
        "./g.ts": "sql.exec(String.raw`SELECT ${x}`)",
        "./h.ts": "sql.exec(['SELECT', x].join(' '))",
        "./i.ts": "sql . exec ( text )",
        "./j.ts": 'ctx.storage.sql.exec("SELECT 1")',
        "./k.ts": '// sql.exec(`${x}`)\n/* storage.sql.exec(x + y) */\nconst a = "s"',
        "./m.ts": "sql.exec<{ id: string }>(`SELECT ${x}`)",
        "./l.ts": "sql.exec(\"SELECT ?\", x)\nsql.exec('SELECT 1')\nsql.exec(`SELECT 2`)",
        "./store.ts": "this.#storage.sql.exec(query.text, ...query.params)\nsql.exec(query.text + x)",
      }),
    ).toEqual([
      "./a.ts: exec(`SELECT * FROM events WHERE id = '${id}'`)",
      './b.ts: exec("SELECT * FROM events WHERE id = \'" + id + "\'")',
      "./b.ts: reads .sql",
      "./c.ts: exec(query)",
      "./c.ts: reads .sql",
      './d.ts: exec("SELECT 1" + "-- " + x)',
      "./e.ts: exec(query.text)",
      "./f.ts: exec(`SELECT ${columns} FROM events`)",
      "./g.ts: exec(String.raw`SELECT ${x}`)",
      "./h.ts: exec(['SELECT', x].join(' '))",
      "./i.ts: exec(text)",
      "./j.ts: reads .sql",
      "./m.ts: exec(`SELECT ${x}`)",
      "./store.ts: exec(query.text + x)",
    ]);
  });
});
