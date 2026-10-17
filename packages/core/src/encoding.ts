/**
 * The small decoding and shape checks every package uses, kept in one place so that each is written once: hex, the
 * 32-byte hex key or id, a JSON object, strict UTF-8 and JSON text. None of them throws.
 */
export { bytesToHex } from "@noble/hashes/utils.js";

/**
 * `TextDecoder` and `atob` are globals of every runtime this code runs in (Workers and Node); core's `lib` has no DOM
 * types, so the parts used here are declared.
 */
declare const TextDecoder: new (
  label: "utf-8",
  options: { fatal: true; ignoreBOM: boolean },
) => { decode(input: Uint8Array): string };
declare function atob(data: string): string;

const HEX_32 = /^[0-9a-f]{64}$/;

/**
 * 32 bytes as 64 lowercase hex characters: an event id, a public key or a sha256. NIP-01: "exact 64-character
 * lowercase hex values".
 */
export function isHex32(value: unknown): value is string {
  return typeof value === "string" && HEX_32.test(value);
}

/** A JSON object: not null and not an array. */
export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Decodes UTF-8 strictly: bytes that are not UTF-8 give undefined instead of U+FFFD. A leading byte order mark is kept
 * as U+FEFF, so no byte is dropped, unless `stripBom` is set.
 */
export function decodeUtf8Strict(bytes: Uint8Array, options: { stripBom?: boolean } = {}): string | undefined {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: options.stripBom !== true }).decode(bytes);
  } catch {
    return undefined;
  }
}

export type JsonParseResult = { readonly ok: true; readonly value: unknown } | { readonly ok: false };

/** JSON.parse without throwing. */
export function parseJsonText(text: string): JsonParseResult {
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch {
    return { ok: false };
  }
}

/**
 * Decodes base64 to bytes with the platform's `atob`. `atob` is forgiving (it skips ASCII whitespace and does not
 * require padding), so the caller checks the exact form it accepts first. Undefined when `atob` refuses the input.
 */
export function decodeBase64(value: string): Uint8Array | undefined {
  let binary: string;
  try {
    binary = atob(value);
  } catch {
    return undefined;
  }
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}
