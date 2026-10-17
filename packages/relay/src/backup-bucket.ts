/**
 * Backups in R2 (DATA-5). One backup is three objects under `backups/<id>/`: the events as JSONL, the allowlist as
 * JSON, and a manifest written last that names both with their sha256, size and, for the events, their count. A
 * backup without a manifest is incomplete and is never restored.
 *
 * The id starts with the time of the run in UTC and ends with random hex, so every run writes new keys. The bucket
 * lock refuses overwriting and deleting within retention; no run relies on writing a key again.
 */
import { bytesToHex, decodeUtf8Strict, parseJsonText } from "@zenith/core";
import * as v from "valibot";
import type { Backup } from "./store.ts";
import { count, hex32, validate } from "./validation.ts";

export const BACKUP_PREFIX = "backups/";
export const MANIFEST_VERSION = 1;

/** `2026-10-18T03-17-00.000Z-0123456789abcdef`: the UTC time of the run, with `-` for `:`, and 64 random bits. */
const BACKUP_ID = /^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.\d{3}Z-[0-9a-f]{16}$/;

export const BACKUP_WRITE_ERRORS = ["write-failed"] as const;
export type BackupWriteError = (typeof BACKUP_WRITE_ERRORS)[number];

export const BACKUP_READ_ERRORS = ["bad-backup-id", "not-found", "bad-manifest", "integrity-mismatch"] as const;
export type BackupReadError = (typeof BACKUP_READ_ERRORS)[number];

export type BackupWriteResult =
  | { readonly ok: true; readonly id: string; readonly events: number }
  | { readonly ok: false; readonly code: BackupWriteError };

export type BackupReadResult =
  | { readonly ok: true; readonly backup: Backup }
  | { readonly ok: false; readonly code: BackupReadError };

type Part = { key: string; sha256: string; bytes: number };
export type BackupManifest = {
  version: typeof MANIFEST_VERSION;
  id: string;
  /** The time of the run, ISO 8601 in UTC. */
  created_at: string;
  events: Part & { count: number };
  allowlist: Part;
};

export function isBackupId(value: unknown): value is string {
  return typeof value === "string" && BACKUP_ID.test(value);
}

/** The id of a backup run at `at` (milliseconds since the epoch). */
export function backupId(at: number): string {
  const random = bytesToHex(crypto.getRandomValues(new Uint8Array(8)));
  return `${new Date(at).toISOString().replaceAll(":", "-")}-${random}`;
}

/** The keys of a backup's objects. */
export function backupKeys(id: string): { events: string; allowlist: string; manifest: string } {
  const base = `${BACKUP_PREFIX}${id}/`;
  return { events: `${base}events.jsonl`, allowlist: `${base}allowlist.json`, manifest: `${base}manifest.json` };
}

/**
 * Writes `backup` as a new backup run at `at` (milliseconds). The events and the allowlist are written first, each
 * checked by R2 against its sha256; the manifest last. Never throws; a failure is a reason code only.
 */
export async function writeBackup(bucket: R2Bucket, backup: Backup, at: number): Promise<BackupWriteResult> {
  const id = backupId(at);
  const keys = backupKeys(id);
  const events = encode(backup.events.map((line) => `${line}\n`).join(""));
  const allowlist = encode(backup.allowlist);
  try {
    const manifest: BackupManifest = {
      version: MANIFEST_VERSION,
      id,
      created_at: new Date(at).toISOString(),
      events: { ...(await put(bucket, keys.events, events, "application/x-ndjson")), count: backup.events.length },
      allowlist: await put(bucket, keys.allowlist, allowlist, "application/json"),
    };
    await put(bucket, keys.manifest, encode(JSON.stringify(manifest)), "application/json");
    return { ok: true, id, events: backup.events.length };
  } catch {
    return { ok: false, code: "write-failed" };
  }
}

/**
 * Reads the backup `id`: its manifest, then the events and the allowlist, each checked against the manifest's size
 * and sha256, and the events against its count. Never throws; anything else is refused as a whole.
 */
export async function readBackup(bucket: R2Bucket, id: unknown): Promise<BackupReadResult> {
  if (!isBackupId(id)) return { ok: false, code: "bad-backup-id" };
  const keys = backupKeys(id);
  const manifestBytes = await get(bucket, keys.manifest);
  if (manifestBytes === undefined) return { ok: false, code: "not-found" };
  const parsed = parseManifest(manifestBytes, id, keys);
  if (!parsed.ok) return parsed;
  const { manifest } = parsed;
  const events = await get(bucket, keys.events);
  const allowlist = await get(bucket, keys.allowlist);
  if (events === undefined || allowlist === undefined) return { ok: false, code: "not-found" };
  if (!(await matches(events, manifest.events)) || !(await matches(allowlist, manifest.allowlist))) {
    return { ok: false, code: "integrity-mismatch" };
  }
  const text = decodeUtf8Strict(events);
  const allowlistText = decodeUtf8Strict(allowlist);
  if (text === undefined || allowlistText === undefined) return { ok: false, code: "integrity-mismatch" };
  if (text !== "" && !text.endsWith("\n")) return { ok: false, code: "integrity-mismatch" };
  const lines = text === "" ? [] : text.slice(0, -1).split("\n");
  if (lines.length !== manifest.events.count) return { ok: false, code: "integrity-mismatch" };
  return { ok: true, backup: { events: lines, allowlist: allowlistText } };
}

async function put(bucket: R2Bucket, key: string, bytes: Uint8Array, contentType: string): Promise<Part> {
  const sha256 = await sha256Hex(bytes);
  const written = await bucket.put(key, bytes, { sha256, httpMetadata: { contentType } });
  if (written === null) throw new Error("not written");
  return { key, sha256, bytes: bytes.byteLength };
}

async function get(bucket: R2Bucket, key: string): Promise<Uint8Array | undefined> {
  try {
    const object = await bucket.get(key);
    return object === null ? undefined : new Uint8Array(await object.arrayBuffer());
  } catch {
    return undefined;
  }
}

async function matches(bytes: Uint8Array, part: Part): Promise<boolean> {
  return bytes.byteLength === part.bytes && (await sha256Hex(bytes)) === part.sha256;
}

type ManifestParseResult =
  | { readonly ok: true; readonly manifest: BackupManifest }
  | { readonly ok: false; readonly code: "bad-manifest" };

/** A part of the manifest, which must name the key the id gives: a manifest never points at another object. */
function partSchema(key: string) {
  return v.object({ key: v.literal(key), sha256: hex32, bytes: count });
}

/** The manifest of the backup `id`: its version, its own id, and parts that name the keys of that id. */
function parseManifest(bytes: Uint8Array, id: string, keys: ReturnType<typeof backupKeys>): ManifestParseResult {
  const text = decodeUtf8Strict(bytes);
  const parsed = text === undefined ? undefined : parseJsonText(text);
  if (parsed?.ok !== true) return { ok: false, code: "bad-manifest" };
  const schema = v.object({
    version: v.literal(MANIFEST_VERSION),
    id: v.literal(id),
    created_at: v.string(),
    events: v.object({ ...partSchema(keys.events).entries, count }),
    allowlist: partSchema(keys.allowlist),
  });
  const manifest = validate(schema, parsed.value, "bad-manifest");
  return manifest.ok ? { ok: true, manifest: manifest.value } : manifest;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}

function encode(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}
