// Helpers shared by the tests. Not exported from the package.
import { parseVaultConfig, type VaultConfig } from "./allowlist.ts";
import { EventStore } from "./store.ts";
import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import {
  computeEventId,
  parseFilter,
  verifyEventObject,
  type Filter,
  type UnsignedEvent,
  type VerifiedEvent,
} from "@zenith/core";

/** A test-only secret key derived from a fixed label. */
export function testSecretKey(label: string): Uint8Array {
  return sha256(utf8ToBytes(`zenith test key ${label}`));
}

export function publicKeyOf(secretKey: Uint8Array): string {
  return bytesToHex(schnorr.getPublicKey(secretKey));
}

/** Signs the template and runs it through verification, the only way to obtain a VerifiedEvent. */
export function signVerified(template: Partial<UnsignedEvent>, secretKey: Uint8Array): VerifiedEvent {
  const unsigned: UnsignedEvent = {
    pubkey: publicKeyOf(secretKey),
    created_at: 1_700_000_000,
    kind: 1,
    tags: [],
    content: "",
    ...template,
  };
  const id = computeEventId(unsigned);
  const sig = bytesToHex(schnorr.sign(hexToBytes(id), secretKey, new Uint8Array(32)));
  const result = verifyEventObject({ ...unsigned, id, sig }, { now: unsigned.created_at });
  if (!result.ok) throw new Error(`test event failed verification: ${result.error.code}`);
  return result.event;
}

export function filterOf(value: unknown): Filter {
  const result = parseFilter(value);
  if (!result.ok) throw new Error(result.error.message);
  return result.filter;
}

/** A configuration whose owner is `owner`. */
export function testConfig(owner: string): VaultConfig {
  const result = parseVaultConfig({ OWNER_PUBKEY: owner });
  if (!result.ok) throw new Error(result.error);
  return result.config;
}

/** Opens a store owned by `owner` with these importers, each with its kinds. */
export function openStore(
  storage: DurableObjectStorage,
  owner: string,
  importers: readonly (readonly [string, readonly number[]])[] = [],
): EventStore {
  const opened = EventStore.open(storage, testConfig(owner), 0);
  if (!opened.ok) throw new Error(`could not open the store: ${opened.error}`);
  const { store } = opened;
  for (const [pubkey, kinds] of importers) {
    const result = store.addKey(pubkey, { role: "importer", kinds }, 0);
    if (!result.changed) throw new Error(`could not add an importer: ${result.reason}`);
  }
  return store;
}
