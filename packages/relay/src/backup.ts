/**
 * The exported form of the vault (DATA-5): events as JSONL, one canonical event JSON (ST-7) per line, and the
 * allowlist as one JSON document with keys, roles, allowed kinds and the revoked keys.
 */
import { parseJsonText } from "@zenith/core";
import * as v from "valibot";
import { isValidGrantKinds, type AllowedKey, type AllowlistState, type RevokedKey } from "./allowlist.ts";
import { count, hex32, validate } from "./validation.ts";

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

/** The exported form; the checks across entries (one owner, no key listed twice) follow in parseAllowlistState. */
const ALLOWLIST_DOCUMENT = v.object({
  version: v.literal(ALLOWLIST_BACKUP_VERSION),
  keys: v.array(
    v.variant("role", [
      v.object({ pubkey: hex32, role: v.literal("owner"), kinds: v.optional(v.never()), added_at: count }),
      v.object({
        pubkey: hex32,
        role: v.literal("importer"),
        kinds: v.pipe(
          v.array(v.number()),
          v.check((kinds) => isValidGrantKinds(kinds)),
        ),
        added_at: count,
      }),
      v.object({
        pubkey: hex32,
        role: v.literal("retired"),
        // A retired former owner keeps no kinds.
        kinds: v.pipe(
          v.array(v.number()),
          v.check((kinds) => kinds.length === 0 || isValidGrantKinds(kinds)),
        ),
        added_at: count,
      }),
    ]),
  ),
  revoked: v.array(v.object({ pubkey: hex32, revoked_at: count })),
});

function parseAllowlistState(text: string): AllowlistState | undefined {
  const parsed = parseJsonText(text);
  if (!parsed.ok) return undefined;
  const document = validate(ALLOWLIST_DOCUMENT, parsed.value, "bad-allowlist");
  if (!document.ok) return undefined;
  const keys: AllowedKey[] = document.value.keys.map((key) =>
    key.role === "owner"
      ? { pubkey: key.pubkey, role: key.role, addedAt: key.added_at }
      : { pubkey: key.pubkey, role: key.role, kinds: key.kinds, addedAt: key.added_at },
  );
  const revoked: RevokedKey[] = document.value.revoked.map((entry) => ({
    pubkey: entry.pubkey,
    revokedAt: entry.revoked_at,
  }));
  const pubkeys = [...keys, ...revoked].map((entry) => entry.pubkey);
  if (new Set(pubkeys).size !== pubkeys.length) return undefined;
  if (keys.filter((key) => key.role === "owner").length > 1) return undefined;
  return { keys, revoked };
}
