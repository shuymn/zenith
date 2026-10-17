/**
 * The allowlist's rules, without SQL: the owner configuration, who may write which kind (WR-1, WR-3), and how a
 * restored allowlist merges with the one already present (ST-8). `EventStore` in store.ts applies them.
 */
import type { VerifiedEvent } from "@zenith/core";
import { isOwnerPubkey } from "./vars.ts";

declare const configured: unique symbol;

/** The vault's configuration, created only by {@link parseVaultConfig}. */
export type VaultConfig = { readonly owner: string; readonly [configured]: true };

export const CONFIG_ERRORS = ["missing-owner", "bad-owner"] as const;
export type ConfigError = (typeof CONFIG_ERRORS)[number];
export type ConfigParseResult = { ok: true; config: VaultConfig } | { ok: false; code: ConfigError };

/** Reads the configuration from the Worker's variables. `OWNER_PUBKEY` is the owner's 64-character lowercase hex key. */
export function parseVaultConfig(vars: { readonly OWNER_PUBKEY?: unknown }): ConfigParseResult {
  const owner = vars.OWNER_PUBKEY;
  if (owner === undefined || owner === "") return { ok: false, code: "missing-owner" };
  if (!isOwnerPubkey(owner)) return { ok: false, code: "bad-owner" };
  // The one place that brands a configuration.
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion
  return { ok: true, config: { owner } as VaultConfig };
}

export const KEY_ROLES = ["owner", "importer", "retired"] as const;
export type KeyRole = (typeof KEY_ROLES)[number];
const ROLE_SET: ReadonlySet<string> = new Set(KEY_ROLES);

export function isKeyRole(value: unknown): value is KeyRole {
  return typeof value === "string" && ROLE_SET.has(value);
}

/**
 * A key on the allowlist. The owner writes every kind but 62; an importer only its kinds; a retired key nothing.
 * A retired key keeps the kinds it had, as a record.
 */
export type AllowedKey =
  | { readonly pubkey: string; readonly role: "owner"; readonly addedAt: number }
  | {
      readonly pubkey: string;
      readonly role: "importer" | "retired";
      readonly kinds: readonly number[];
      readonly addedAt: number;
    };

/** A key removed from the allowlist. It stays recorded so that neither an add nor a restore brings it back (ST-8). */
export type RevokedKey = { readonly pubkey: string; readonly revokedAt: number };

export type AllowlistState = { readonly keys: readonly AllowedKey[]; readonly revoked: readonly RevokedKey[] };

/** What the admin route may add. The owner comes from the configuration only, so it cannot be added. */
export type KeyGrant = { readonly role: "importer"; readonly kinds: readonly number[] };

export const ALLOWLIST_REFUSALS = [
  "bad-pubkey",
  "bad-kinds",
  "owner-key",
  "already-listed",
  "revoked-key",
  "not-listed",
  "unchanged",
] as const;
export type AllowlistRefusal = (typeof ALLOWLIST_REFUSALS)[number];

/**
 * The result of an allowlist operation. When it is ok the allowlist changed, and the caller closes every connection
 * (OPS-2), so that no subscription keeps the authority it had before.
 */
export type AllowlistResult = { readonly ok: true } | { readonly ok: false; readonly code: AllowlistRefusal };

/** NIP-62: "Kind `62` requests a specific relay to delete everything, including NIP-09 Deletion Events". */
export const VANISH_KIND = 62;

export const WRITE_REJECTIONS = ["vanish-request", "unknown-key", "retired-key", "kind-not-allowed"] as const;
export type WriteRejection = (typeof WRITE_REJECTIONS)[number];

/**
 * How an `OK` message answers each rejection. NIP-01 lists `blocked: please register your pubkey at ...` for a key
 * the relay does not accept, and NIP-42 uses `restricted:` for a key "still not allowed by the relay or is exceeding
 * its authorization"; a listed key writing a kind outside its grant exceeds its authorization.
 */
const WRITE_REJECTION_RESPONSES: Record<WriteRejection, { prefix: "blocked" | "restricted"; message: string }> = {
  // WR-3
  "vanish-request": { prefix: "blocked", message: "requests to vanish are not accepted" },
  "unknown-key": { prefix: "blocked", message: "this key may not write here" },
  "retired-key": { prefix: "blocked", message: "this key is retired" },
  "kind-not-allowed": { prefix: "restricted", message: "this key may not write this kind" },
};

export function toRejectionResponse(rejection: WriteRejection): { accepted: false; message: string } {
  const { prefix, message } = WRITE_REJECTION_RESPONSES[rejection];
  return { accepted: false, message: `${prefix}: ${message}` };
}

/** WR-1, WR-3: whether `key` (undefined when not listed) may write `event`; undefined when it may. */
export function checkWrite(event: VerifiedEvent, key: AllowedKey | undefined): WriteRejection | undefined {
  // WR-3: refused for every key, the owner included.
  if (event.kind === VANISH_KIND) return "vanish-request";
  if (key === undefined) return "unknown-key";
  const access = WRITES_BY_ROLE[key.role];
  if (access === "nothing") return "retired-key";
  if (access === "granted-kinds" && !(key.role !== "owner" && key.kinds.includes(event.kind))) {
    return "kind-not-allowed";
  }
  return undefined;
}

/** What each role may write (WR-1); the owner every kind but 62 (WR-3). */
const WRITES_BY_ROLE: Record<KeyRole, "every-kind" | "granted-kinds" | "nothing"> = {
  owner: "every-kind",
  importer: "granted-kinds",
  retired: "nothing",
};

/** Whether the kinds of a grant are valid: at least one, each a kind (0 to 65535), never 62 (WR-3). */
export function isValidGrantKinds(kinds: readonly unknown[]): kinds is readonly number[] {
  return (
    kinds.length > 0 &&
    kinds.every((kind) => Number.isInteger(kind) && typeof kind === "number" && kind >= 0 && kind <= 65535) &&
    !kinds.includes(VANISH_KIND)
  );
}

export const OWNER_CONFLICTS = ["owner-revoked", "owner-retired"] as const;
/** The configured owner is a key that an allowlist records as revoked or retired. */
export type OwnerConflict = (typeof OWNER_CONFLICTS)[number];

/**
 * ST-8: whether `state` records the configured owner as revoked or retired. Making it the owner would reverse that,
 * so the store neither opens nor restores such a state.
 */
export function ownerConflict(state: AllowlistState, config: VaultConfig): OwnerConflict | undefined {
  if (state.revoked.some((entry) => entry.pubkey === config.owner)) return "owner-revoked";
  const key = state.keys.find((entry) => entry.pubkey === config.owner);
  return key?.role === "retired" ? "owner-retired" : undefined;
}

export type MergeResult = { ok: true; state: AllowlistState } | { ok: false; code: OwnerConflict };

/**
 * ST-8: the allowlist after restoring `backup` into a store whose allowlist is `current`. Per key, the more
 * restrictive state wins: revoked over retired over writable. A writable key keeps the current entry when there is one
 * (a backup never widens the kinds of a listed key), and otherwise takes the backup's. The owner is always the
 * configured one: a backup's owner that is not it is restored as retired. When either side records the configured
 * owner as revoked or retired, nothing is merged.
 */
export function mergeAllowlists(current: AllowlistState, backup: AllowlistState, config: VaultConfig): MergeResult {
  const conflict = ownerConflict(current, config) ?? ownerConflict(backup, config);
  if (conflict !== undefined) return { ok: false, code: conflict };
  const revoked = new Map<string, RevokedKey>();
  for (const entry of [...current.revoked, ...backup.revoked]) {
    const seen = revoked.get(entry.pubkey);
    if (seen === undefined || entry.revokedAt < seen.revokedAt) revoked.set(entry.pubkey, entry);
  }
  const currentKeys = new Map(current.keys.map((key) => [key.pubkey, key]));
  const backupKeys = new Map(backup.keys.map((key) => [key.pubkey, key]));
  const keys: AllowedKey[] = [];
  for (const pubkey of new Set([...currentKeys.keys(), ...backupKeys.keys()])) {
    if (revoked.has(pubkey)) continue;
    const mine = currentKeys.get(pubkey);
    const theirs = backupKeys.get(pubkey);
    if (pubkey === config.owner) {
      keys.push({ pubkey, role: "owner", addedAt: earliest(mine, theirs) });
      continue;
    }
    const restored = theirs === undefined ? undefined : demoteForeignOwner(theirs);
    const retired = mine?.role === "retired" || restored?.role === "retired";
    const base = mine ?? restored;
    if (base === undefined) continue;
    keys.push(retired ? retire(base, earliest(mine, theirs)) : { ...base, addedAt: earliest(mine, theirs) });
  }
  return { ok: true, state: { keys: keys.toSorted(byPubkey), revoked: [...revoked.values()].toSorted(byPubkey) } };
}

/** The retired form of a key; a former owner keeps no kinds. */
export function retire(key: AllowedKey, addedAt = key.addedAt): AllowedKey {
  return { pubkey: key.pubkey, role: "retired", kinds: key.role === "owner" ? [] : key.kinds, addedAt };
}

function demoteForeignOwner(key: AllowedKey): AllowedKey {
  return key.role === "owner" ? retire(key) : key;
}

function earliest(a: AllowedKey | undefined, b: AllowedKey | undefined): number {
  return Math.min(a?.addedAt ?? Number.POSITIVE_INFINITY, b?.addedAt ?? Number.POSITIVE_INFINITY);
}

function byPubkey(a: { pubkey: string }, b: { pubkey: string }): number {
  if (a.pubkey === b.pubkey) return 0;
  return a.pubkey < b.pubkey ? -1 : 1;
}
