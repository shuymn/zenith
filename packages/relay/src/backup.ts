/**
 * The exported form of the vault (DATA-5): events as JSONL, one canonical event JSON (ST-7) per line, and the
 * allowlist as one JSON document with keys, roles, allowed kinds and the revoked keys.
 */
import { isHex32, isRecord, parseJsonText } from "@zenith/core";
import { isKeyRole, isValidGrantKinds, type AllowedKey, type AllowlistState, type RevokedKey } from "./allowlist.ts";

export const ALLOWLIST_BACKUP_VERSION = 1;

type AllowlistDocument = {
  version: typeof ALLOWLIST_BACKUP_VERSION;
  keys: (
    | { pubkey: string; role: "owner"; added_at: number }
    | { pubkey: string; role: "importer" | "retired"; kinds: readonly number[]; added_at: number }
  )[];
  revoked: { pubkey: string; revoked_at: number }[];
};

export function formatAllowlist(state: AllowlistState): string {
  const document: AllowlistDocument = {
    version: ALLOWLIST_BACKUP_VERSION,
    keys: state.keys.map((key) =>
      key.role === "owner"
        ? { pubkey: key.pubkey, role: key.role, added_at: key.addedAt }
        : { pubkey: key.pubkey, role: key.role, kinds: key.kinds, added_at: key.addedAt },
    ),
    revoked: state.revoked.map((entry) => ({ pubkey: entry.pubkey, revoked_at: entry.revokedAt })),
  };
  return JSON.stringify(document);
}

export const ALLOWLIST_PARSE_ERRORS = ["bad-allowlist"] as const;
export type AllowlistParseError = (typeof ALLOWLIST_PARSE_ERRORS)[number];
export type AllowlistParseResult =
  | { readonly ok: true; readonly state: AllowlistState }
  | { readonly ok: false; readonly code: AllowlistParseError };

/** Parses an exported allowlist. Never throws; anything not in the exported form is refused as a whole. */
export function parseAllowlist(text: string): AllowlistParseResult {
  const state = parseAllowlistState(text);
  return state === undefined ? { ok: false, code: "bad-allowlist" } : { ok: true, state };
}

function parseAllowlistState(text: string): AllowlistState | undefined {
  const parsed = parseJsonText(text);
  if (!parsed.ok) return undefined;
  const { value } = parsed;
  if (!isRecord(value) || value["version"] !== ALLOWLIST_BACKUP_VERSION) return undefined;
  const { keys, revoked } = value;
  if (!Array.isArray(keys) || !Array.isArray(revoked)) return undefined;
  const parsedKeys: AllowedKey[] = [];
  const seen = new Set<string>();
  for (const item of keys as unknown[]) {
    const key = parseKey(item);
    if (key === undefined || seen.has(key.pubkey)) return undefined;
    seen.add(key.pubkey);
    parsedKeys.push(key);
  }
  if (parsedKeys.filter((key) => key.role === "owner").length > 1) return undefined;
  const parsedRevoked: RevokedKey[] = [];
  for (const item of revoked as unknown[]) {
    if (!isRecord(item) || !isHex32(item["pubkey"])) return undefined;
    if (!isTimestamp(item["revoked_at"]) || seen.has(item["pubkey"])) return undefined;
    seen.add(item["pubkey"]);
    parsedRevoked.push({ pubkey: item["pubkey"], revokedAt: item["revoked_at"] });
  }
  return { keys: parsedKeys, revoked: parsedRevoked };
}

function parseKey(item: unknown): AllowedKey | undefined {
  if (!isRecord(item)) return undefined;
  const { pubkey, role, kinds, added_at: addedAt } = item;
  if (!isHex32(pubkey) || !isKeyRole(role) || !isTimestamp(addedAt)) return undefined;
  if (role === "owner") return kinds === undefined ? { pubkey, role, addedAt } : undefined;
  if (!Array.isArray(kinds)) return undefined;
  const values: unknown[] = kinds;
  // A retired former owner keeps no kinds.
  if (!(role === "retired" && values.length === 0) && !isValidGrantKinds(values)) return undefined;
  return { pubkey, role, kinds: values.filter((kind): kind is number => typeof kind === "number"), addedAt };
}

function isTimestamp(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}
