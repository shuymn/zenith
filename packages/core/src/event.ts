import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { DEFAULT_EVENT_LIMITS, type EventLimits } from "./limits.ts";
import { utf8ByteLength } from "./utf8.ts";

export type NostrEvent = {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
};

export type UnsignedEvent = Omit<NostrEvent, "id" | "sig">;

declare const verified: unique symbol;

/**
 * An event whose structure, id and signature were checked by {@link verifyEvent} or {@link verifyEventObject},
 * the only functions that create one. APIs that must not see unverified input take this type.
 */
export type VerifiedEvent = NostrEvent & { readonly [verified]: true };

export type EventRejectionCode =
  | "too-large"
  | "malformed-json"
  | "not-object"
  | "bad-id"
  | "bad-pubkey"
  | "bad-sig"
  | "bad-kind"
  | "bad-created-at"
  | "bad-tags"
  | "bad-content"
  | "too-many-tags"
  | "tag-too-large"
  | "invalid-unicode"
  | "created-at-too-far-in-future"
  | "id-mismatch"
  | "bad-signature";

export type EventRejection = {
  /** Machine-readable prefix of a NIP-01 `OK` message. */
  prefix: "invalid";
  code: EventRejectionCode;
  /** Human-readable part of a NIP-01 `OK` message. */
  message: string;
  /** The event's `id` field, present when it is a well-formed id, for the `OK` message. */
  eventId?: string;
};

export type EventVerification = { ok: true; event: VerifiedEvent } | { ok: false; error: EventRejection };

export type VerifyEventOptions = {
  /** Current time in unix seconds. Defaults to the system clock. */
  now?: number;
  limits?: Partial<EventLimits>;
};

const HEX_32_BYTES = /^[0-9a-f]{64}$/;
const HEX_64_BYTES = /^[0-9a-f]{128}$/;

/**
 * Serializes the event for its id as NIP-01 requires. Only the seven characters NIP-01
 * lists are escaped; every other character, including other control characters, is
 * included verbatim. Tag strings follow the same rule as `content`.
 */
export function serializeEvent(event: UnsignedEvent): string {
  return serializeWith(event, escapeNip01);
}

/**
 * NIP-01 says only seven characters are escaped, but nostr-tools (JSON.stringify) and strfry
 * (taocpp/json) escape the other control characters as \u00XX, so their ids differ for such events.
 * This serialization follows JSON.stringify so that events signed by those clients still verify.
 */
function serializeJsonStringifyCompatible(event: UnsignedEvent): string {
  return serializeWith(event, escapeJsonStringify);
}

function serializeWith(event: UnsignedEvent, escape: (code: number) => string | undefined): string {
  const str = (value: string) => serializeString(value, escape);
  const tags = event.tags.map((tag) => `[${tag.map(str).join(",")}]`).join(",");
  return `[0,${str(event.pubkey)},${event.created_at},${event.kind},[${tags}],${str(event.content)}]`;
}

/**
 * Computes the event id as the lowercase hex sha256 of the UTF-8 serialization.
 * @throws {RangeError} when a string contains a lone surrogate, which has no UTF-8 encoding.
 */
export function computeEventId(event: UnsignedEvent): string {
  return hashSerialized(serializeEvent(event));
}

function hashSerialized(serialized: string): string {
  if (!serialized.isWellFormed()) {
    throw new RangeError("event contains a lone surrogate");
  }
  return bytesToHex(sha256(utf8ToBytes(serialized)));
}

/**
 * Parses and verifies an event from the raw JSON text as received. Never throws.
 * Nothing is cached: every call re-checks the structure, recomputes the id and verifies the signature.
 */
export function verifyEvent(raw: string, options: VerifyEventOptions = {}): EventVerification {
  const limits = resolveLimits(options);
  // A UTF-8 encoding is never shorter than the UTF-16 length, so skip counting for oversized input.
  if (raw.length > limits.maxEventBytes || utf8ByteLength(raw) > limits.maxEventBytes) {
    return reject("too-large", `event exceeds ${limits.maxEventBytes} bytes`);
  }
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    return reject("malformed-json", "event is not valid JSON");
  }
  return verifyParsed(value, limits, options.now);
}

/**
 * Verifies an already parsed event value. The raw size limit does not apply; use
 * {@link verifyEvent} for input received from a client. Never throws.
 */
export function verifyEventObject(value: unknown, options: VerifyEventOptions = {}): EventVerification {
  return verifyParsed(value, resolveLimits(options), options.now);
}

/** Formats a rejection as the message of a NIP-01 `OK` or `CLOSED` message. */
export function formatOkMessage(rejection: EventRejection): string {
  return `${rejection.prefix}: ${rejection.message}`;
}

function verifyParsed(value: unknown, limits: EventLimits, now: number | undefined): EventVerification {
  if (!isRecord(value)) return reject("not-object", "event is not a JSON object");
  const { id, pubkey, created_at, kind, tags, content, sig } = value;
  const eventId = typeof id === "string" && HEX_32_BYTES.test(id) ? id : undefined;
  const fail = (code: EventRejectionCode, message: string) => reject(code, message, eventId);

  if (eventId === undefined) return fail("bad-id", "id must be 64 lowercase hex characters");
  if (typeof pubkey !== "string" || !HEX_32_BYTES.test(pubkey)) {
    return fail("bad-pubkey", "pubkey must be 64 lowercase hex characters");
  }
  if (typeof sig !== "string" || !HEX_64_BYTES.test(sig)) {
    return fail("bad-sig", "sig must be 128 lowercase hex characters");
  }
  if (!isIntegerInRange(kind, 0, 65535)) {
    return fail("bad-kind", "kind must be an integer between 0 and 65535");
  }
  if (!isIntegerInRange(created_at, 0, Number.MAX_SAFE_INTEGER)) {
    return fail("bad-created-at", "created_at must be a non-negative integer");
  }
  if (!isTags(tags)) return fail("bad-tags", "tags must be an array of non-empty arrays of strings");
  if (typeof content !== "string") return fail("bad-content", "content must be a string");

  if (tags.length > limits.maxTags) return fail("too-many-tags", `more than ${limits.maxTags} tags`);
  for (const tag of tags) {
    for (const item of tag) {
      if (utf8ByteLength(item) > limits.maxTagValueBytes) {
        return fail("tag-too-large", `a tag value exceeds ${limits.maxTagValueBytes} bytes`);
      }
      if (!item.isWellFormed()) return fail("invalid-unicode", "tag contains a lone surrogate");
    }
  }
  if (!content.isWellFormed()) return fail("invalid-unicode", "content contains a lone surrogate");

  const currentTime = now ?? Math.floor(Date.now() / 1000);
  if (created_at > currentTime + limits.maxFutureSeconds) {
    return fail("created-at-too-far-in-future", "created_at is too far in the future");
  }

  const event: NostrEvent = {
    id: eventId,
    pubkey,
    created_at,
    kind,
    tags: tags.map((tag) => [...tag]),
    content,
    sig,
  };
  if (!matchesId(event)) return fail("id-mismatch", "id does not match the event data");
  if (!verifySignature(sig, eventId, pubkey)) return fail("bad-signature", "signature verification failed");
  // The id and signature were just verified, so this is the one place that brands an event.
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion
  return { ok: true, event: event as VerifiedEvent };
}

function verifySignature(sig: string, id: string, pubkey: string): boolean {
  try {
    return schnorr.verify(hexToBytes(sig), hexToBytes(id), hexToBytes(pubkey));
  } catch {
    return false;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isIntegerInRange(value: unknown, min: number, max: number): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= min && value <= max;
}

function matchesId(event: NostrEvent): boolean {
  if (computeEventId(event) === event.id) return true;
  // The JSON.stringify-compatible form differs only when a string has a control character
  // outside the seven NIP-01 escapes, so only then is it worth computing.
  if (![event.content, ...event.tags.flat()].some(hasNonNip01ControlChar)) return false;
  return hashSerialized(serializeJsonStringifyCompatible(event)) === event.id;
}

function hasNonNip01ControlChar(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code < 0x20 && escapeNip01(code) === undefined) return true;
  }
  return false;
}

// NIP-01: "Each tag is an array of one or more strings".
function isTags(value: unknown): value is string[][] {
  if (!Array.isArray(value)) return false;
  // for...of visits holes in sparse arrays as undefined, unlike every(), so they are rejected here.
  for (const tag of value as unknown[]) {
    if (!Array.isArray(tag) || tag.length === 0) return false;
    for (const item of tag as unknown[]) {
      if (typeof item !== "string") return false;
    }
  }
  return true;
}

function resolveLimits(options: VerifyEventOptions): EventLimits {
  return { ...DEFAULT_EVENT_LIMITS, ...options.limits };
}

function reject(code: EventRejectionCode, message: string, eventId?: string): EventVerification {
  const error: EventRejection = { prefix: "invalid", code, message };
  if (eventId !== undefined) error.eventId = eventId;
  return { ok: false, error };
}

function serializeString(value: string, escapeChar: (code: number) => string | undefined): string {
  let out = '"';
  let start = 0;
  for (let i = 0; i < value.length; i++) {
    const escaped = escapeChar(value.charCodeAt(i));
    if (escaped !== undefined) {
      out += value.slice(start, i) + escaped;
      start = i + 1;
    }
  }
  return `${out}${value.slice(start)}"`;
}

function escapeJsonStringify(code: number): string | undefined {
  const escaped = escapeNip01(code);
  if (escaped !== undefined || code >= 0x20) return escaped;
  return `\\u${code.toString(16).padStart(4, "0")}`;
}

function escapeNip01(code: number): string | undefined {
  switch (code) {
    case 0x0a:
      return "\\n";
    case 0x22:
      return '\\"';
    case 0x5c:
      return "\\\\";
    case 0x0d:
      return "\\r";
    case 0x09:
      return "\\t";
    case 0x08:
      return "\\b";
    case 0x0c:
      return "\\f";
    default:
      return undefined;
  }
}
