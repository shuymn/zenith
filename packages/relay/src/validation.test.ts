/**
 * The inputs the relay checks with Valibot (validation.ts): admin commands (OPS-1), the allowlist of a backup and a
 * backup's manifest (DATA-5, ST-8). Each case pins what is accepted, with the value it gives, and what is refused, with
 * its code.
 */
import { isRecord } from "@zenith/core";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { parseAdminCommand } from "./admin.ts";
import { backupKeys, readBackup, writeBackup } from "./backup-bucket.ts";
import { parseAllowlist } from "./backup.ts";

const B = "b".repeat(64);
const C = "c".repeat(64);
const encoder = new TextEncoder();

function document(keys: unknown[], revoked: unknown[] = []): string {
  return JSON.stringify({ version: 1, keys, revoked });
}

/** Writes a backup, then replaces its manifest with `change` applied to it, and reads the backup. */
async function readWithManifest(change: (manifest: Record<string, unknown>) => unknown): Promise<unknown> {
  const written = await writeBackup(env.BACKUPS, { events: [], allowlist: "{}" }, Date.now());
  if (!written.ok) throw new Error(written.code);
  const key = backupKeys(written.id).manifest;
  const manifest: unknown = JSON.parse((await (await env.BACKUPS.get(key))?.text()) ?? "");
  if (!isRecord(manifest)) throw new Error("the manifest is not an object");
  const replaced = change(structuredClone(manifest));
  await env.BACKUPS.put(key, typeof replaced === "string" ? replaced : JSON.stringify(replaced));
  return readBackup(env.BACKUPS, written.id);
}

/** One part of a manifest, as an object to change. */
function part(manifest: Record<string, unknown>, name: "events" | "allowlist"): Record<string, unknown> {
  const value = manifest[name];
  if (!isRecord(value)) throw new Error(`the manifest has no ${name} part`);
  return value;
}

describe("OPS-1: parseAdminCommand", () => {
  it.each([
    ['{"op":"list"}', { op: "list" }],
    ['{"op":"backup"}', { op: "backup" }],
    [`{"op":"retire","pubkey":"${B}"}`, { op: "retire", pubkey: B }],
    [`{"op":"revoke","pubkey":"${B}"}`, { op: "revoke", pubkey: B }],
    // Only the type of the kinds is checked here; the store refuses a grant it does not accept (WR-1, WR-3).
    [`{"op":"add","pubkey":"${B}","kinds":[1,1.5,-1,62]}`, { op: "add", pubkey: B, kinds: [1, 1.5, -1, 62] }],
    [`{"op":"add","pubkey":"${B}","kinds":[]}`, { op: "add", pubkey: B, kinds: [] }],
    ['{"op":"restore","backup":"anything"}', { op: "restore", backup: "anything" }],
    [' \n{"op":"list"}\n ', { op: "list" }],
  ])("accepts %s", (text, command) => {
    expect(parseAdminCommand(encoder.encode(text))).toEqual({ ok: true, command });
  });

  it.each([
    ["an empty body", ""],
    ["null", "null"],
    ["a string", '"list"'],
    ["no op", "{}"],
    ["an op of another type", '{"op":1}'],
    ["an op in another case", '{"op":"LIST"}'],
    ["a __proto__ field", '{"op":"list","__proto__":{}}'],
    ["an extra field on add", `{"op":"add","pubkey":"${B}","kinds":[1],"role":"owner"}`],
    ["a pubkey of 63 characters", `{"op":"retire","pubkey":"${B.slice(1)}"}`],
    ["a pubkey that is not a string", '{"op":"revoke","pubkey":1}'],
    ["kinds that are null", `{"op":"add","pubkey":"${B}","kinds":null}`],
    ["a kind that is null", `{"op":"add","pubkey":"${B}","kinds":[null]}`],
    ["a missing pubkey", '{"op":"add","kinds":[1]}'],
    ["a backup id that is not a string", '{"op":"restore","backup":1}'],
    ["a byte order mark", '﻿{"op":"list"}'],
  ])("refuses %s", (_name, text) => {
    expect(parseAdminCommand(encoder.encode(text))).toEqual({ ok: false, code: "bad-command" });
  });

  it("refuses bytes that are not UTF-8", () => {
    expect(parseAdminCommand(new Uint8Array([0x7b, 0xff, 0x7d]))).toEqual({ ok: false, code: "bad-command" });
  });
});

describe("ST-8: parseAllowlist", () => {
  it("accepts the exported form, ignoring fields it does not know", () => {
    const text = JSON.stringify({
      version: 1,
      note: "ignored",
      keys: [
        { pubkey: B, role: "owner", added_at: 0, note: "ignored" },
        { pubkey: C, role: "retired", kinds: [], added_at: Number.MAX_SAFE_INTEGER },
      ],
      revoked: [{ pubkey: "d".repeat(64), revoked_at: 5, note: "ignored" }],
    });
    expect(parseAllowlist(text)).toEqual({
      ok: true,
      state: {
        keys: [
          { pubkey: B, role: "owner", addedAt: 0 },
          { pubkey: C, role: "retired", kinds: [], addedAt: Number.MAX_SAFE_INTEGER },
        ],
        revoked: [{ pubkey: "d".repeat(64), revokedAt: 5 }],
      },
    });
  });

  it.each([
    ["an owner with kinds", document([{ pubkey: B, role: "owner", kinds: [], added_at: 0 }])],
    ["an owner with null kinds", document([{ pubkey: B, role: "owner", kinds: null, added_at: 0 }])],
    ["an importer with a fractional kind", document([{ pubkey: B, role: "importer", kinds: [1.5], added_at: 0 }])],
    ["an importer with a string kind", document([{ pubkey: B, role: "importer", kinds: ["1"], added_at: 0 }])],
    ["a retired key without kinds", document([{ pubkey: B, role: "retired", added_at: 0 }])],
    ["a retired key with kind 62", document([{ pubkey: B, role: "retired", kinds: [62], added_at: 0 }])],
    ["a fractional added_at", document([{ pubkey: B, role: "owner", added_at: 1.5 }])],
    ["a negative added_at", document([{ pubkey: B, role: "owner", added_at: -1 }])],
    ["an unsafe added_at", document([{ pubkey: B, role: "owner", added_at: 2 ** 53 }])],
    ["an uppercase key", document([{ pubkey: B.toUpperCase(), role: "owner", added_at: 0 }])],
    ["an uppercase revoked key", document([], [{ pubkey: B.toUpperCase(), revoked_at: 0 }])],
    [
      "a revoked key twice",
      document(
        [],
        [
          { pubkey: B, revoked_at: 0 },
          { pubkey: B, revoked_at: 1 },
        ],
      ),
    ],
    ["keys that are not an array", JSON.stringify({ version: 1, keys: {}, revoked: [] })],
    ["no revoked list", JSON.stringify({ version: 1, keys: [] })],
    ["a version as a string", JSON.stringify({ version: "1", keys: [], revoked: [] })],
    ["an array", "[]"],
  ])("refuses %s", (_name, text) => {
    expect(parseAllowlist(text)).toEqual({ ok: false, code: "bad-allowlist" });
  });
});

describe("DATA-5: the manifest of a backup", () => {
  it("reads a manifest with fields it does not know", async () => {
    expect(
      await readWithManifest((manifest) => {
        part(manifest, "events")["note"] = "ignored";
        return { ...manifest, note: "ignored" };
      }),
    ).toEqual({ ok: true, backup: { events: [], allowlist: "{}" } });
  });

  it.each([
    ["not JSON", () => "{"],
    ["a byte order mark", (manifest: Record<string, unknown>) => `﻿${JSON.stringify(manifest)}`],
    ["another version", (manifest: Record<string, unknown>) => ({ ...manifest, version: 2 })],
    ["another id", (manifest: Record<string, unknown>) => ({ ...manifest, id: "x" })],
    ["no created_at", (manifest: Record<string, unknown>) => ({ ...manifest, created_at: undefined })],
    ["a numeric created_at", (manifest: Record<string, unknown>) => ({ ...manifest, created_at: 0 })],
    [
      "events naming the allowlist's key",
      (manifest: Record<string, unknown>) => {
        part(manifest, "events")["key"] = part(manifest, "allowlist")["key"];
        return manifest;
      },
    ],
    [
      "an uppercase sha256",
      (manifest: Record<string, unknown>) => {
        const allowlist = part(manifest, "allowlist");
        allowlist["sha256"] = String(allowlist["sha256"]).toUpperCase();
        return manifest;
      },
    ],
    [
      "a negative size",
      (manifest: Record<string, unknown>) => {
        part(manifest, "allowlist")["bytes"] = -1;
        return manifest;
      },
    ],
    [
      "a fractional size",
      (manifest: Record<string, unknown>) => {
        part(manifest, "events")["bytes"] = 0.5;
        return manifest;
      },
    ],
    [
      "no count",
      (manifest: Record<string, unknown>) => {
        delete part(manifest, "events")["count"];
        return manifest;
      },
    ],
    [
      "a count on the allowlist only",
      (manifest: Record<string, unknown>) => {
        const count = part(manifest, "events")["count"];
        delete part(manifest, "events")["count"];
        part(manifest, "allowlist")["count"] = count;
        return manifest;
      },
    ],
    ["parts that are not objects", (manifest: Record<string, unknown>) => ({ ...manifest, events: [] })],
  ])("refuses a manifest with %s", async (_name, change) => {
    expect(await readWithManifest(change)).toEqual({ ok: false, code: "bad-manifest" });
  });
});
