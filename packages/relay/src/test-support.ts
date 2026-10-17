// Helpers shared by the tests. Not exported from the package.
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
