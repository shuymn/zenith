import type { NostrEvent } from "./event.ts";
import { DEFAULT_FILTER_LIMITS, type FilterLimits } from "./limits.ts";

/** A parsed NIP-01 filter. An absent attribute places no condition; an empty set matches nothing. */
export type Filter = {
  readonly ids?: ReadonlySet<string>;
  readonly authors?: ReadonlySet<string>;
  readonly kinds?: ReadonlySet<number>;
  /** Tag conditions keyed by the single-letter tag name, case-sensitive. */
  readonly tags: ReadonlyMap<string, ReadonlySet<string>>;
  readonly since?: number;
  readonly until?: number;
  /** The requested limit as sent; {@link resolveLimit} applies the upper bound. */
  readonly limit?: number;
};

export type FilterRejectionCode =
  | "not-object"
  | "unsupported-key"
  | "bad-value"
  | "too-many-values"
  | "no-filters"
  | "too-many-filters"
  | "bad-subscription-id";

export type FilterRejection = {
  /** Machine-readable prefix of a NIP-01 `CLOSED` message. */
  prefix: "invalid" | "unsupported";
  code: FilterRejectionCode;
  /** Human-readable part of a NIP-01 `CLOSED` message. */
  message: string;
};

export type FilterParseResult = { ok: true; filter: Filter } | { ok: false; error: FilterRejection };
export type FiltersParseResult = { ok: true; filters: Filter[] } | { ok: false; error: FilterRejection };
export type SubscriptionIdParseResult = { ok: true; subscriptionId: string } | { ok: false; error: FilterRejection };

const HEX_32_BYTES = /^[0-9a-f]{64}$/;
const TAG_FILTER_KEY = /^#[a-zA-Z]$/;
const MAX_SUBSCRIPTION_ID_LENGTH = 64;

/**
 * Parses the filters of a REQ, rejecting the whole REQ if any filter is invalid.
 * The input is expected to be a value produced by JSON.parse.
 */
export function parseFilters(values: readonly unknown[], limits: Partial<FilterLimits> = {}): FiltersParseResult {
  const resolved = { ...DEFAULT_FILTER_LIMITS, ...limits };
  if (values.length === 0) return reject("no-filters", "REQ has no filters");
  if (values.length > resolved.maxFilters) {
    return reject("too-many-filters", `more than ${resolved.maxFilters} filters`);
  }
  const filters: Filter[] = [];
  for (const value of values) {
    const result = parseFilter(value, resolved);
    if (!result.ok) return result;
    filters.push(result.filter);
  }
  return { ok: true, filters };
}

/**
 * Parses one NIP-01 filter. Never throws.
 * The input is expected to be a value produced by JSON.parse.
 */
export function parseFilter(value: unknown, limits: Partial<FilterLimits> = {}): FilterParseResult {
  const { maxFilterValues } = { ...DEFAULT_FILTER_LIMITS, ...limits };
  if (!isRecord(value)) return reject("not-object", "filter is not a JSON object");

  const filter: {
    ids?: Set<string>;
    authors?: Set<string>;
    kinds?: Set<number>;
    tags: Map<string, Set<string>>;
    since?: number;
    until?: number;
    limit?: number;
  } = { tags: new Map() };
  let valueCount = 0;

  for (const [key, item] of Object.entries(value)) {
    if (key === "since" || key === "until" || key === "limit") {
      if (!isNonNegativeInteger(item)) return reject("bad-value", `${key} must be a non-negative integer`);
      filter[key] = item;
      continue;
    }

    // Decide whether the key is supported before counting its values.
    if (key !== "ids" && key !== "authors" && key !== "kinds" && !TAG_FILTER_KEY.test(key)) {
      return reject("unsupported-key", `filter contains an unsupported key: ${key}`, "unsupported");
    }
    if (!Array.isArray(item)) return reject("bad-value", `${key} must be an array`);
    const values: unknown[] = item;
    valueCount += values.length;
    if (valueCount > maxFilterValues) return reject("too-many-values", `more than ${maxFilterValues} values`);

    if (key === "kinds") {
      const kinds: number[] = [];
      for (const kind of values) {
        if (!isKind(kind)) return reject("bad-value", "kinds must be integers between 0 and 65535");
        kinds.push(kind);
      }
      filter.kinds = new Set(kinds);
    } else if (key === "ids" || key === "authors" || key === "#e" || key === "#p") {
      // NIP-01: these lists "MUST contain exact 64-character lowercase hex values".
      const hex = stringsOf(values, (v) => HEX_32_BYTES.test(v));
      if (hex === undefined) return reject("bad-value", `${key} must contain 64-character lowercase hex values`);
      if (key === "ids" || key === "authors") filter[key] = new Set(hex);
      else filter.tags.set(key.slice(1), new Set(hex));
    } else {
      const strings = stringsOf(values, () => true);
      if (strings === undefined) return reject("bad-value", `${key} must contain strings`);
      filter.tags.set(key.slice(1), new Set(strings));
    }
  }
  return { ok: true, filter };
}

/**
 * NIP-01: "an arbitrary, non-empty string of max length 64 chars". Characters are counted as code points.
 * The input is expected to be a value produced by JSON.parse.
 */
export function parseSubscriptionId(value: unknown): SubscriptionIdParseResult {
  if (typeof value !== "string" || value.length === 0 || !value.isWellFormed()) {
    return reject("bad-subscription-id", "subscription id must be a non-empty string");
  }
  // Iterating a well-formed string yields code points; only count up to one past the limit.
  let length = 0;
  for (const _ of value) {
    if (++length > MAX_SUBSCRIPTION_ID_LENGTH) {
      return reject("bad-subscription-id", `subscription id is longer than ${MAX_SUBSCRIPTION_ID_LENGTH} characters`);
    }
  }
  return { ok: true, subscriptionId: value };
}

/** Attributes are combined with AND, values within a list with OR. Values are compared as plain strings. */
export function matchesFilter(event: NostrEvent, filter: Filter): boolean {
  if (filter.ids !== undefined && !filter.ids.has(event.id)) return false;
  if (filter.authors !== undefined && !filter.authors.has(event.pubkey)) return false;
  if (filter.kinds !== undefined && !filter.kinds.has(event.kind)) return false;
  if (filter.since !== undefined && event.created_at < filter.since) return false;
  if (filter.until !== undefined && event.created_at > filter.until) return false;
  for (const [name, values] of filter.tags) {
    // NIP-01: "Only the first value in any given tag is indexed."
    const found = event.tags.some((tag) => tag[0] === name && tag[1] !== undefined && values.has(tag[1]));
    if (!found) return false;
  }
  return true;
}

/** Multiple filters are combined with OR. */
export function matchesAnyFilter(event: NostrEvent, filters: readonly Filter[]): boolean {
  return filters.some((filter) => matchesFilter(event, filter));
}

/** The number of stored events to return: the requested limit capped at `maxLimit`, or `maxLimit` when absent. */
export function resolveLimit(filter: Filter, limits: Partial<FilterLimits> = {}): number {
  const { maxLimit } = { ...DEFAULT_FILTER_LIMITS, ...limits };
  return Math.min(filter.limit ?? maxLimit, maxLimit);
}

/** NIP-01: "When `limit` is zero, the relay MUST NOT return stored events for that filter." */
export function returnsStoredEvents(filter: Filter): boolean {
  return filter.limit !== 0;
}

/** Formats a rejection as the message of a NIP-01 `CLOSED` message. */
export function formatClosedMessage(rejection: FilterRejection): string {
  return `${rejection.prefix}: ${rejection.message}`;
}

/** Returns the values when all are strings accepted by `accept`; checks every index so holes are rejected. */
function stringsOf(values: unknown[], accept: (value: string) => boolean): string[] | undefined {
  const strings: string[] = [];
  for (const value of values) {
    if (typeof value !== "string" || !accept(value)) return undefined;
    strings.push(value);
  }
  return strings;
}

function isKind(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 65535;
}

function isNonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function reject(
  code: FilterRejectionCode,
  message: string,
  prefix: FilterRejection["prefix"] = "invalid",
): { ok: false; error: FilterRejection } {
  return { ok: false, error: { prefix, code, message } };
}
