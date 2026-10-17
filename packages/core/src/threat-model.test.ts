/**
 * The threat model and the tests agree: every invariant that docs/threat-model.md marks _Enforced (main)_ cites test
 * files that exist, and each cited file names the invariant's ID in a test name or a comment. An ID in a test is how
 * `grep -rn 'RD-1' packages` shows its coverage ("How to use" in the threat model).
 */
import { describe, expect, it } from "vitest";

declare global {
  interface ImportMeta {
    glob<T>(patterns: string | string[], options: { query: string; import: string; eager: true }): Record<string, T>;
  }
}

const threatModel =
  import.meta.glob<string>("../../../docs/threat-model.md", { query: "?raw", import: "default", eager: true })[
    "../../../docs/threat-model.md"
  ] ?? "";

// Every test file of every package, keyed by its path from the repository root.
const testFiles = Object.fromEntries(
  Object.entries(
    import.meta.glob<string>("../../*/src/**/*.test.ts", { query: "?raw", import: "default", eager: true }),
  ).map(([path, source]) => [fromRoot(path), source]),
);

/** A glob key as a path from the repository root: this package's files come as `./`, the others as `../../`. */
function fromRoot(path: string): string {
  if (path.startsWith("./")) return `packages/core/src/${path.slice(2)}`;
  if (path.startsWith("../../")) return `packages/${path.slice(6)}`;
  throw new Error(`unexpected glob key ${path}`);
}

type Invariant = { readonly id: string; readonly text: string };

/** The invariants of the document: each `- **ID: ...**` bullet with its continuation lines, as one line. */
function invariants(document: string): Invariant[] {
  const found: Invariant[] = [];
  let current: { id: string; lines: string[] } | undefined;
  for (const line of document.split("\n")) {
    const start = /^- \*\*([A-Z]+-\d+):/.exec(line);
    if (start?.[1] !== undefined) {
      if (current !== undefined) found.push({ id: current.id, text: current.lines.join(" ").replaceAll(/\s+/g, " ") });
      current = { id: start[1], lines: [line] };
    } else if (current !== undefined && /^\s+\S/.test(line)) {
      current.lines.push(line);
    } else if (current !== undefined) {
      found.push({ id: current.id, text: current.lines.join(" ").replaceAll(/\s+/g, " ") });
      current = undefined;
    }
  }
  if (current !== undefined) found.push({ id: current.id, text: current.lines.join(" ").replaceAll(/\s+/g, " ") });
  return found;
}

/**
 * The test files an invariant's text cites, as paths from the repository root. A bare file name (`events.ws.test.ts`)
 * names the file of that name in the directory of the last full path cited before it.
 */
function citedTests(text: string): string[] {
  const cited: string[] = [];
  let directory: string | undefined;
  for (const match of text.matchAll(/`([^`\s]*\.test\.ts)`/g)) {
    const path = match[1] ?? "";
    if (path.includes("/")) {
      directory = path.slice(0, path.lastIndexOf("/") + 1);
      cited.push(path);
    } else {
      cited.push(`${directory ?? "<no directory>/"}${path}`);
    }
  }
  return [...new Set(cited)];
}

/** `RD-1` but not `RD-10`. */
function namesId(source: string, id: string): boolean {
  return new RegExp(`\\b${id}(?!\\d)`).test(source);
}

/**
 * How an enforced part is pinned ("How an invariant is pinned" in the threat model). Every kind but configuration is a
 * test, so an invariant pinned by one of them cites at least one test file; an invariant pinned by configuration only
 * may cite none.
 */
const PINNED_BY_TEST = /Pinned by (?:behavior|source analysis|log redaction|schema)/;
const PINNED_BY_CONFIGURATION = /Pinned by configuration/;

/** Problems with the citations of every invariant marked _Enforced (main)_. */
function citationProblems(document: string, files: Readonly<Record<string, string>>): string[] {
  const problems: string[] = [];
  for (const { id, text } of invariants(document)) {
    if (!text.includes("Enforced (main)")) continue;
    const cited = citedTests(text);
    if (PINNED_BY_TEST.test(text)) {
      if (cited.length === 0) problems.push(`${id}: cites no test`);
    } else if (!PINNED_BY_CONFIGURATION.test(text)) {
      problems.push(`${id}: does not say how it is pinned`);
    }
    for (const path of cited) {
      const source = files[path];
      if (source === undefined) problems.push(`${id}: ${path} does not exist`);
      else if (!namesId(source, id)) problems.push(`${id}: ${path} does not name ${id}`);
    }
  }
  return problems;
}

describe("the threat model's citations of tests", () => {
  it("reads the threat model and the test files of every package", () => {
    const enforced = invariants(threatModel).filter(({ text }) => text.includes("Enforced (main)"));
    // Guards against a parser that silently finds nothing to compare.
    expect(enforced.length).toBeGreaterThanOrEqual(25);
    expect(enforced.flatMap(({ text }) => citedTests(text)).length).toBeGreaterThanOrEqual(40);
    expect(Object.keys(testFiles)).toEqual(
      expect.arrayContaining(["packages/core/src/event.test.ts", "packages/relay/src/protocol.ws.test.ts"]),
    );
  });

  it("finds every cited test file, and the invariant's ID in it", () => {
    expect(citationProblems(threatModel, testFiles)).toEqual([]);
  });

  it("detects a missing file, a missing ID, no cited test and no way of pinning", () => {
    const document = [
      "### Example (EX)",
      "",
      '- **EX-1: a rule.** _Enforced (main):_ `packages/a/src/a.test.ts` ("EX-1") and `b.test.ts`. _Pinned by behavior._',
      "- **EX-2: another rule.** _Enforced (main):_ `packages/a/src/missing.test.ts`. _Pinned by behavior._",
      '- **EX-3: a third rule.** _Enforced (main):_ `packages/a/src/a.test.ts` ("EX-3"), but the file names EX-30. _Pinned by behavior._',
      "- **EX-4: a planned rule.** _Planned (4)._ `packages/a/src/missing.test.ts`.",
      "- **EX-5: a rule over",
      "  two lines.** _Enforced",
      "  (main):_ `packages/a/src/b.test.ts`. _Pinned by behavior._",
      "- **EX-6: a rule without a test.** _Enforced (main):_ `packages/a/src/a.ts`. _Pinned by behavior._",
      "- **EX-7: a configured rule.** _Enforced (main):_ `packages/a/config.json`. _Pinned by configuration._",
      "- **EX-8: a rule that does not say.** _Enforced (main):_ `packages/a/src/a.ts`.",
      "",
    ].join("\n");
    expect(
      citationProblems(document, {
        "packages/a/src/a.test.ts": "// EX-1, EX-30\n",
        "packages/a/src/b.test.ts": "it('EX-1: works')\n",
      }),
    ).toEqual([
      "EX-2: packages/a/src/missing.test.ts does not exist",
      "EX-3: packages/a/src/a.test.ts does not name EX-3",
      "EX-5: packages/a/src/b.test.ts does not name EX-5",
      "EX-6: cites no test",
      "EX-8: does not say how it is pinned",
    ]);
  });
});
