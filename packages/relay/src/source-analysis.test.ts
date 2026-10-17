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
  }
  return found;
}

describe("source analysis of packages/relay", () => {
  it("sees the source tree without test files", () => {
    expect(Object.keys(sources)).toEqual(expect.arrayContaining(["./store.ts", "./sql.ts", "./index.ts"]));
    expect(Object.keys(sources).filter((file) => file.endsWith(".test.ts") || file === "./test-support.ts")).toEqual(
      [],
    );
  });

  it("RES-2: passes no interpolated or concatenated SQL to exec, and reads .sql only in the store", () => {
    expect(violations(sources)).toEqual([]);
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
