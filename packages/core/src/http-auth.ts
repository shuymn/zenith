/**
 * NIP-98 HTTP Auth: an `Authorization: Nostr <base64>` header carrying a signed kind 27235 event that names the
 * request's URL, method and, for a request with a body, the body's sha256. Pure: the caller passes the request's
 * absolute URL, method, body and the current time, and decides who may act with the returned key (OPS-1).
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { verifyEvent, type VerifiedEvent } from "./event.ts";
import { DEFAULT_HTTP_AUTH_LIMITS, type HttpAuthLimits } from "./limits.ts";

/**
 * `TextDecoder` is a global of every runtime core runs in (Workers and Node); core's `lib` has no DOM types, so the
 * part used here is declared. `fatal` makes bytes that are not UTF-8 an error instead of U+FFFD.
 */
declare const TextDecoder: new (label: "utf-8", options: { fatal: true }) => { decode(input: Uint8Array): string };

export const HTTP_AUTH_REJECTION_CODES = [
  "missing",
  "bad-scheme",
  "too-large",
  "bad-encoding",
  "bad-event",
  "wrong-kind",
  "stale",
  "url-mismatch",
  "method-mismatch",
  "payload-missing",
  "payload-mismatch",
] as const;
export type HttpAuthRejectionCode = (typeof HTTP_AUTH_REJECTION_CODES)[number];

export type HttpAuthVerification =
  | { readonly ok: true; readonly pubkey: string }
  | { readonly ok: false; readonly code: HttpAuthRejectionCode };

export type HttpAuthOptions = {
  /** The absolute request URL, query included, that the `u` tag must equal. */
  url: string;
  /** The request's HTTP method, which the `method` tag must equal. */
  method: string;
  /** The request body as received; empty for a request without one. */
  body: Uint8Array;
  /** Current time in unix seconds. */
  now: number;
  limits?: Partial<HttpAuthLimits>;
};

/** NIP-98: "A `kind 27235` (In reference to RFC 7235) event is used." */
const HTTP_AUTH_KIND = 27235;

/** RFC 7235: `credentials = auth-scheme [ 1*SP ( token68 / ... ) ]`; the scheme is case-insensitive. */
const CREDENTIALS = /^nostr +([^ ]+)$/i;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}(?:==)?|[A-Za-z0-9+/]{3}=?)?$/;
const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Verifies a NIP-98 `Authorization` header for a request. The event is verified from its decoded text by
 * {@link verifyEvent} (id and signature, EV-1), then checked as NIP-98 lists: "Servers MUST perform the following
 * checks in order to validate the event": the kind, `created_at` within the time window, the `u` tag, the `method`
 * tag; then the `payload` tag. Never throws.
 */
export function verifyHttpAuth(
  authorization: string | null | undefined,
  options: HttpAuthOptions,
): HttpAuthVerification {
  const limits = { ...DEFAULT_HTTP_AUTH_LIMITS, ...options.limits };
  if (authorization === null || authorization === undefined || authorization === "") return reject("missing");
  const value = CREDENTIALS.exec(authorization)?.[1];
  if (value === undefined) return reject("bad-scheme");
  // Four base64 characters carry three bytes; checked before anything is decoded.
  if (value.length > Math.ceil(limits.maxEventBytes / 3) * 4) return reject("too-large");
  const text = decodeBase64Utf8(value);
  if (text === undefined) return reject("bad-encoding");

  const verified = verifyEvent(text, { now: options.now, limits: { maxEventBytes: limits.maxEventBytes } });
  if (!verified.ok) return reject("bad-event");
  const { event } = verified;
  if (event.kind !== HTTP_AUTH_KIND) return reject("wrong-kind");
  // NIP-98: "The `created_at` timestamp MUST be within a reasonable time window (suggestion 60 seconds)."
  if (Math.abs(event.created_at - options.now) > limits.maxClockSkewSeconds) return reject("stale");
  // NIP-98: "The `u` tag MUST be exactly the same as the absolute request URL (including query parameters)."
  if (firstTagValue(event, "u") !== options.url) return reject("url-mismatch");
  // NIP-98: "The `method` tag MUST be the same HTTP method used for the requested resource."
  if (firstTagValue(event, "method") !== options.method) return reject("method-mismatch");
  // NIP-98: clients "SHOULD include a SHA256 hash of the request body in a `payload` tag as hex", and servers "MAY
  // check this". It is required here for every request with a body, so that a signed header authorizes one body.
  const payload = event.tags.find((tag) => tag[0] === "payload");
  if (payload === undefined) return options.body.length > 0 ? reject("payload-missing") : accept(event);
  if (payload[1] !== bytesToHex(sha256(options.body))) return reject("payload-mismatch");
  return accept(event);
}

function accept(event: VerifiedEvent): HttpAuthVerification {
  return { ok: true, pubkey: event.pubkey };
}

function reject(code: HttpAuthRejectionCode): HttpAuthVerification {
  return { ok: false, code };
}

function firstTagValue(event: VerifiedEvent, name: string): string | undefined {
  return event.tags.find((tag) => tag[0] === name)?.[1];
}

/** Standard base64 (RFC 4648 section 4), padding optional, decoded as UTF-8; undefined when it is neither. */
function decodeBase64Utf8(value: string): string | undefined {
  if (value.length % 4 === 1 || !BASE64.test(value)) return undefined;
  const digits = value.replace(/=+$/, "");
  const bytes = new Uint8Array(Math.floor((digits.length * 6) / 8));
  let buffer = 0;
  let bits = 0;
  let index = 0;
  for (const char of digits) {
    buffer = ((buffer << 6) | BASE64_ALPHABET.indexOf(char)) & 0xffffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes[index++] = (buffer >> bits) & 0xff;
    }
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return undefined;
  }
}
