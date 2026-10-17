import { parseJsonText } from "./encoding.ts";
import { parseSubscriptionId } from "./filter.ts";
import { DEFAULT_CONNECTION_LIMITS, type ConnectionLimits } from "./limits.ts";
import { utf8ByteLength } from "./utf8.ts";

/** NIP-01's client messages (`EVENT`, `REQ`, `CLOSE`) and NIP-42's `AUTH`. */
export const CLIENT_MESSAGE_TYPES = ["EVENT", "REQ", "CLOSE", "AUTH"] as const;
export type ClientMessageType = (typeof CLIENT_MESSAGE_TYPES)[number];
const CLIENT_MESSAGE_TYPE_SET: ReadonlySet<string> = new Set(CLIENT_MESSAGE_TYPES);

/**
 * A client message. `EVENT` and `AUTH` carry the event as the text it was received in, not as a parsed value: the
 * only way to use it is `verifyEvent`, which measures that text against the event size limit (EV-1, RES-1).
 */
export type ClientMessage =
  | { readonly type: "EVENT"; readonly eventText: string }
  | { readonly type: "AUTH"; readonly eventText: string }
  | { readonly type: "REQ"; readonly subscriptionId: string; readonly filters: readonly unknown[] }
  | { readonly type: "CLOSE"; readonly subscriptionId: string };

export const MESSAGE_REJECTION_CODES = [
  "too-large",
  "malformed-json",
  "not-message",
  "unknown-type",
  "bad-shape",
  "bad-subscription-id",
] as const;
export type MessageRejectionCode = (typeof MESSAGE_REJECTION_CODES)[number];

export type MessageRejection = {
  /** Machine-readable prefix of a NIP-01 `NOTICE` message. */
  prefix: "invalid";
  code: MessageRejectionCode;
  message: string;
};

export type MessageParseResult = { ok: true; message: ClientMessage } | { ok: false; error: MessageRejection };

/**
 * Parses a WebSocket text message as received. The UTF-8 size is checked before the text is parsed (RES-1). Never
 * throws.
 */
export function parseClientMessage(raw: string, limits: Partial<ConnectionLimits> = {}): MessageParseResult {
  const { maxMessageBytes } = { ...DEFAULT_CONNECTION_LIMITS, ...limits };
  // A UTF-8 encoding is never shorter than the UTF-16 length, so skip counting for oversized input.
  if (raw.length > maxMessageBytes || utf8ByteLength(raw) > maxMessageBytes) {
    return reject("too-large", `message exceeds ${maxMessageBytes} bytes`);
  }
  const parsed = parseJsonText(raw);
  if (!parsed.ok) return reject("malformed-json", "message is not valid JSON");
  const { value } = parsed;
  // NIP-01: client messages "must be JSON arrays".
  if (!Array.isArray(value) || typeof value[0] !== "string") {
    return reject("not-message", "message must be a JSON array that starts with its type");
  }
  const elements: unknown[] = value;
  const type = elements[0];
  if (!isClientMessageType(type)) return reject("unknown-type", "unknown message type");
  return PARSERS[type](raw, elements);
}

function isClientMessageType(value: unknown): value is ClientMessageType {
  return typeof value === "string" && CLIENT_MESSAGE_TYPE_SET.has(value);
}

type Parser = (raw: string, elements: readonly unknown[]) => MessageParseResult;

const PARSERS: Record<ClientMessageType, Parser> = {
  // NIP-01: `["EVENT", <event JSON as defined above>]`.
  EVENT: (raw, elements) => eventMessage("EVENT", raw, elements),
  // NIP-42: `["AUTH", <signed-event-json>]`.
  AUTH: (raw, elements) => eventMessage("AUTH", raw, elements),
  // NIP-01: `["REQ", <subscription_id>, <filters1>, <filters2>, ...]`. parseFilters checks the filters.
  REQ: (_raw, elements) => {
    if (elements.length < 2) return reject("bad-shape", "REQ needs a subscription id");
    const id = parseSubscriptionId(elements[1]);
    if (!id.ok) return reject("bad-subscription-id", id.error.message);
    return { ok: true, message: { type: "REQ", subscriptionId: id.subscriptionId, filters: elements.slice(2) } };
  },
  // NIP-01: `["CLOSE", <subscription_id>]`.
  CLOSE: (_raw, elements) => {
    if (elements.length !== 2) return reject("bad-shape", "CLOSE takes one subscription id");
    const id = parseSubscriptionId(elements[1]);
    if (!id.ok) return reject("bad-subscription-id", id.error.message);
    return { ok: true, message: { type: "CLOSE", subscriptionId: id.subscriptionId } };
  },
};

function eventMessage(type: "EVENT" | "AUTH", raw: string, elements: readonly unknown[]): MessageParseResult {
  if (elements.length !== 2) return reject("bad-shape", `${type} takes one event`);
  const texts = elementTexts(raw);
  const eventText = texts[1];
  // The split agrees with JSON.parse on every valid array; a disagreement is refused rather than guessed at.
  if (eventText === undefined || texts.length !== 2) {
    return reject("malformed-json", "message is not valid JSON");
  }
  return { ok: true, message: { type, eventText } };
}

const QUOTE = 0x22;
const BACKSLASH = 0x5c;
const COMMA = 0x2c;
const OPENERS: ReadonlySet<number> = new Set([0x5b, 0x7b]); // [ {
const CLOSERS: ReadonlySet<number> = new Set([0x5d, 0x7d]); // ] }

/**
 * The texts of the elements of the top-level array in `raw`, without the whitespace around them. `raw` is text that
 * JSON.parse accepted as an array, so tracking strings and nesting is enough to find the top-level commas.
 */
function elementTexts(raw: string): string[] {
  const texts: string[] = [];
  let depth = 0;
  let inString = false;
  let start = 0;
  for (let i = 0; i < raw.length; i++) {
    const code = raw.charCodeAt(i);
    if (inString) {
      if (code === BACKSLASH) i++;
      else if (code === QUOTE) inString = false;
      continue;
    }
    if (code === QUOTE) {
      inString = true;
    } else if (OPENERS.has(code)) {
      depth++;
      if (depth === 1) start = i + 1;
    } else if (CLOSERS.has(code)) {
      if (depth === 1) texts.push(raw.slice(start, i).trim());
      depth--;
    } else if (code === COMMA && depth === 1) {
      texts.push(raw.slice(start, i).trim());
      start = i + 1;
    }
  }
  return texts;
}

/** Formats a rejection as the message of a NIP-01 `NOTICE` message. */
export function formatNoticeMessage(rejection: MessageRejection): string {
  return `${rejection.prefix}: ${rejection.message}`;
}

function reject(code: MessageRejectionCode, message: string): { ok: false; error: MessageRejection } {
  return { ok: false, error: { prefix: "invalid", code, message } };
}
