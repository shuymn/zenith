import { describe, expect, it } from "vitest";
import type { NostrEvent } from "./event.ts";
import {
  formatClosedMessage,
  matchesAnyFilter,
  matchesFilter,
  parseFilter,
  parseFilters,
  parseSubscriptionId,
  resolveLimit,
  returnsStoredEvents,
  type Filter,
  type FilterParseResult,
  type FilterRejection,
} from "./filter.ts";

const ID = "a".repeat(64);
const OTHER_ID = "b".repeat(64);
const PUBKEY = "c".repeat(64);
const OTHER_PUBKEY = "d".repeat(64);
const CREATED_AT = 1_700_000_000;

// Matching does not check signatures, so a structurally valid event is enough here.
const EVENT: NostrEvent = {
  id: ID,
  pubkey: PUBKEY,
  created_at: CREATED_AT,
  kind: 1,
  tags: [
    ["e", OTHER_ID, "wss://relay.example.com"],
    ["p", OTHER_PUBKEY],
    ["t", "nostr", "second"],
    ["T", "upper"],
    ["r"],
  ],
  content: "",
  sig: "0".repeat(128),
};

function filterOf(value: unknown): Filter {
  const result = parseFilter(value);
  if (!result.ok) throw new Error(`expected the filter to parse: ${result.error.message}`);
  return result.filter;
}

function errorOf(result: { ok: true } | { ok: false; error: FilterRejection }): FilterRejection {
  if (result.ok) throw new Error("expected a rejection");
  return result.error;
}

function matches(value: unknown, event: NostrEvent = EVENT): boolean {
  return matchesFilter(event, filterOf(value));
}

describe("parseFilter", () => {
  it("accepts every NIP-01 attribute", () => {
    expect(
      parseFilter({
        ids: [ID],
        authors: [PUBKEY],
        kinds: [1],
        "#e": [OTHER_ID],
        "#t": ["nostr"],
        since: 0,
        until: CREATED_AT,
        limit: 10,
      }).ok,
    ).toBe(true);
  });

  it("accepts an empty filter", () => {
    expect(parseFilter({}).ok).toBe(true);
  });

  // NIP-01: "The `ids`, `authors`, `#e` and `#p` filter lists MUST contain exact 64-character lowercase hex values."
  it.each([
    ["uppercase id", { ids: [ID.toUpperCase()] }],
    ["63-character id", { ids: [ID.slice(1)] }],
    ["id prefix", { ids: ["aaaa"] }],
    ["percent sign id", { ids: ["%"] }],
    ["uppercase author", { authors: [PUBKEY.toUpperCase()] }],
    ["65-character author", { authors: [`${PUBKEY}0`] }],
    ["uppercase #e", { "#e": [OTHER_ID.toUpperCase()] }],
    ["SQL in #e", { "#e": ["' OR 1=1--"] }],
    ["63-character #p", { "#p": [OTHER_PUBKEY.slice(1)] }],
  ])("rejects a non-hex value: %s", (_name, value) => {
    expect(errorOf(parseFilter(value))).toMatchObject({ prefix: "invalid", code: "bad-value" });
  });

  it.each([
    ["ids not an array", { ids: ID }],
    ["number in ids", { ids: [1] }],
    ["null in authors", { authors: [null] }],
    ["string kind", { kinds: ["1"] }],
    ["fractional kind", { kinds: [1.5] }],
    ["kind 65536", { kinds: [65536] }],
    ["negative kind", { kinds: [-1] }],
    ["number in a tag filter", { "#t": [1] }],
    ["tag filter not an array", { "#t": "nostr" }],
    ["fractional since", { since: 1.5 }],
    ["string until", { until: "1" }],
    ["negative since", { since: -1 }],
    ["negative limit", { limit: -1 }],
    ["fractional limit", { limit: 0.5 }],
    ["null limit", { limit: null }],
    ["undefined in ids", { ids: Array.from({ length: 2 }, (_, i) => (i === 0 ? ID : undefined)) }],
  ])("rejects a value of the wrong type: %s", (_name, value) => {
    expect(errorOf(parseFilter(value))).toMatchObject({ prefix: "invalid", code: "bad-value" });
  });

  it.each([null, [], "filter", 1])("rejects a non-object filter %j", (value) => {
    expect(errorOf(parseFilter(value))).toMatchObject({ prefix: "invalid", code: "not-object" });
  });

  it.each(["search", "__proto__", "#", "#tt", "#1", "#é", "ids "])("rejects the unsupported key %j", (key) => {
    const value = JSON.parse(`{${JSON.stringify(key)}:[]}`);
    expect(errorOf(parseFilter(value))).toMatchObject({ prefix: "unsupported", code: "unsupported-key" });
  });

  it.each(["search", "#tt", "#1"])("rejects the unsupported key %j before counting its values", (key) => {
    const huge = Array.from({ length: 1001 }, () => "x");
    expect(errorOf(parseFilter({ [key]: huge }))).toMatchObject({ prefix: "unsupported", code: "unsupported-key" });
    expect(errorOf(parseFilter({ kinds: [1], [key]: huge }, { maxFilterValues: 1 })).code).toBe("unsupported-key");
  });

  it("accepts exactly 1000 values in total and rejects 1001", () => {
    const authors = Array.from({ length: 500 }, () => PUBKEY);
    const kinds = Array.from({ length: 250 }, (_, i) => i);
    const tags = Array.from({ length: 250 }, (_, i) => String(i));
    expect(parseFilter({ authors, kinds, "#t": tags }).ok).toBe(true);
    expect(errorOf(parseFilter({ authors, kinds, "#t": tags, "#u": ["x"] }))).toMatchObject({
      prefix: "invalid",
      code: "too-many-values",
    });
  });

  it("applies an overridden value limit", () => {
    expect(errorOf(parseFilter({ kinds: [1, 2] }, { maxFilterValues: 1 })).code).toBe("too-many-values");
  });

  it("keeps a large limit for resolveLimit to cap", () => {
    expect(parseFilter({ limit: 1_000_000 }).ok).toBe(true);
  });
});

describe("parseFilters", () => {
  it("accepts 10 filters and rejects 11", () => {
    expect(parseFilters(Array.from({ length: 10 }, () => ({})))).toMatchObject({ ok: true });
    expect(errorOf(parseFilters(Array.from({ length: 11 }, () => ({}))))).toMatchObject({
      prefix: "invalid",
      code: "too-many-filters",
    });
  });

  it("rejects a REQ without filters", () => {
    expect(errorOf(parseFilters([]))).toMatchObject({ prefix: "invalid", code: "no-filters" });
  });

  it("rejects the whole REQ when one filter is invalid", () => {
    expect(errorOf(parseFilters([{}, { ids: ["%"] }])).code).toBe("bad-value");
  });

  it("applies an overridden filter limit", () => {
    expect(errorOf(parseFilters([{}, {}], { maxFilters: 1 })).code).toBe("too-many-filters");
  });
});

describe("parseSubscriptionId", () => {
  // NIP-01: "<subscription_id> is an arbitrary, non-empty string of max length 64 chars."
  it.each(["a", "a".repeat(64), "日".repeat(64), "\u{1F600}".repeat(64), "' OR 1=1--"])("accepts %j", (id) => {
    expect(parseSubscriptionId(id)).toEqual({ ok: true, subscriptionId: id });
  });

  it.each([
    ["empty", ""],
    ["65 characters", "a".repeat(65)],
    ["65 emoji", "\u{1F600}".repeat(65)],
    ["a number", 1],
    ["null", null],
    ["a lone surrogate", "\uD800"],
  ])("rejects %s", (_name, value) => {
    expect(errorOf(parseSubscriptionId(value))).toMatchObject({ prefix: "invalid", code: "bad-subscription-id" });
  });
});

describe("matchesFilter", () => {
  it("matches everything with an empty filter", () => {
    expect(matches({})).toBe(true);
  });

  // NIP-01: "If any of these lists is empty, no event can satisfy that condition, so the filter
  // MUST NOT match any events. An empty list MUST NOT be treated as if the attribute were absent."
  it.each([{ ids: [] }, { authors: [] }, { kinds: [] }, { "#t": [] }])("matches nothing with %j", (value) => {
    expect(matches(value)).toBe(false);
  });

  it("matches by id, author and kind as list membership", () => {
    expect(matches({ ids: [OTHER_ID, ID] })).toBe(true);
    expect(matches({ ids: [OTHER_ID] })).toBe(false);
    expect(matches({ authors: [PUBKEY] })).toBe(true);
    expect(matches({ authors: [OTHER_PUBKEY] })).toBe(false);
    expect(matches({ kinds: [0, 1] })).toBe(true);
    expect(matches({ kinds: [0] })).toBe(false);
  });

  // NIP-01: "an event matches a filter if `since <= created_at <= until` holds."
  it("treats since and until as inclusive", () => {
    expect(matches({ since: CREATED_AT, until: CREATED_AT })).toBe(true);
    expect(matches({ since: CREATED_AT + 1 })).toBe(false);
    expect(matches({ until: CREATED_AT - 1 })).toBe(false);
  });

  it("requires every attribute to match", () => {
    expect(matches({ authors: [PUBKEY], kinds: [1], "#t": ["nostr"] })).toBe(true);
    expect(matches({ authors: [PUBKEY], kinds: [2], "#t": ["nostr"] })).toBe(false);
    expect(matches({ "#t": ["nostr"], "#p": [PUBKEY] })).toBe(false);
  });

  it("matches tags on the first value of tags with the same name", () => {
    expect(matches({ "#e": [OTHER_ID] })).toBe(true);
    expect(matches({ "#p": [OTHER_PUBKEY] })).toBe(true);
    expect(matches({ "#t": ["other", "nostr"] })).toBe(true);
  });

  // NIP-01: "Only the first value in any given tag is indexed."
  it("does not match on values after the first", () => {
    expect(matches({ "#t": ["second"] })).toBe(false);
  });

  it("does not match a tag without a value", () => {
    expect(matches({ "#r": [""] })).toBe(false);
  });

  it("treats tag names case-sensitively", () => {
    expect(matches({ "#T": ["upper"] })).toBe(true);
    expect(matches({ "#t": ["upper"] })).toBe(false);
    expect(matches({ "#T": ["nostr"] })).toBe(false);
  });

  it("compares values as plain strings", () => {
    const event = { ...EVENT, tags: [["t", "a.*"]] };
    expect(matches({ "#t": ["a.*"] }, event)).toBe(true);
    expect(matches({ "#t": [".*"] }, event)).toBe(false);
    expect(matches({ "#t": ["a%"] }, event)).toBe(false);
    expect(matches({ "#t": ["A.*"] }, event)).toBe(false);
  });
});

describe("matchesAnyFilter", () => {
  it("matches when any filter matches", () => {
    expect(matchesAnyFilter(EVENT, [filterOf({ kinds: [2] }), filterOf({ authors: [PUBKEY] })])).toBe(true);
    expect(matchesAnyFilter(EVENT, [filterOf({ kinds: [2] }), filterOf({ ids: [] })])).toBe(false);
  });
});

describe("limit", () => {
  it("caps the limit at 500 by default and uses the cap when absent", () => {
    expect(resolveLimit(filterOf({ limit: 10 }))).toBe(10);
    expect(resolveLimit(filterOf({ limit: 500 }))).toBe(500);
    expect(resolveLimit(filterOf({ limit: 501 }))).toBe(500);
    expect(resolveLimit(filterOf({}))).toBe(500);
  });

  it("applies an overridden cap", () => {
    expect(resolveLimit(filterOf({ limit: 50 }), { maxLimit: 20 })).toBe(20);
  });

  // NIP-01: "When `limit` is zero, the relay MUST NOT return stored events for that filter."
  it("returns no stored events only for limit 0", () => {
    expect(returnsStoredEvents(filterOf({ limit: 0 }))).toBe(false);
    expect(resolveLimit(filterOf({ limit: 0 }))).toBe(0);
    expect(returnsStoredEvents(filterOf({ limit: 1 }))).toBe(true);
    expect(returnsStoredEvents(filterOf({}))).toBe(true);
  });

  it("still matches new events for a limit 0 filter", () => {
    expect(matches({ limit: 0 })).toBe(true);
  });
});

describe("formatClosedMessage", () => {
  it("formats a rejection with its machine-readable prefix", () => {
    const result: FilterParseResult = parseFilter({ search: "x" });
    expect(formatClosedMessage(errorOf(result))).toMatch(/^unsupported: \S/);
  });
});
