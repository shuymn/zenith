import * as fc from "fast-check";
import { describe, expect, it } from "vitest";
import { verifyEvent, type NostrEvent, type VerifiedEvent } from "./event.ts";
import { matchesAnyFilter, parseFilter, type Filter } from "./filter.ts";
import { apply, canonicalEvents, EMPTY_STATE, query, toOkResponse, type ApplyOutcome } from "./model.ts";
import type { ModelState } from "./model.ts";
import { publicKeyOf, signVerified, testSecretKey } from "./test-support.ts";

const KEY_A = testSecretKey("A");
const KEY_B = testSecretKey("B");
const A = publicKeyOf(KEY_A);
const B = publicKeyOf(KEY_B);
const NOW = 1_000;

function ev(template: Partial<NostrEvent>, key: Uint8Array = KEY_A): VerifiedEvent {
  return signVerified({ created_at: 100, ...template }, key);
}

function run(events: readonly VerifiedEvent[], now = NOW): { state: ModelState; outcomes: ApplyOutcome[] } {
  let state = EMPTY_STATE;
  const outcomes: ApplyOutcome[] = [];
  for (const event of events) {
    const result = apply(state, event, now);
    state = result.state;
    outcomes.push(result.outcome);
  }
  return { state, outcomes };
}

function filterOf(value: unknown): Filter {
  const result = parseFilter(value);
  if (!result.ok) throw new Error(result.error.message);
  return result.filter;
}

function idsOf(state: ModelState, filters: unknown[] = [{}], now = NOW): string[] {
  return query(state, filters.map(filterOf), now).map((event) => event.id);
}

function d(value: string): string[][] {
  return [["d", value]];
}

function lowerIdFirst(a: VerifiedEvent, b: VerifiedEvent): [VerifiedEvent, VerifiedEvent] {
  return a.id < b.id ? [a, b] : [b, a];
}

describe("apply", () => {
  it("stores a regular event and reports a resubmission as a duplicate", () => {
    const note = ev({ kind: 1 });
    const { state, outcomes } = run([note, note]);
    expect(outcomes).toEqual(["stored", "duplicate"]);
    expect(idsOf(state)).toEqual([note.id]);
  });

  it("stores an unknown kind like a regular one", () => {
    const first = ev({ kind: 45, content: "1" });
    const second = ev({ kind: 45, content: "2", created_at: 200 });
    expect(idsOf(run([first, second]).state, [{ kinds: [45] }])).toEqual([second.id, first.id]);
  });

  // WR-5: ephemeral events are never stored, kind 22242 included.
  it.each([20000, 22242, 29999])("WR-5: does not store ephemeral kind %i", (kind) => {
    const { state, outcomes } = run([ev({ kind })]);
    expect(outcomes).toEqual(["not-stored-ephemeral"]);
    expect(canonicalEvents(state)).toEqual([]);
  });

  it.each([19999, 30000])("stores kind %i, outside the ephemeral range", (kind) => {
    expect(run([ev({ kind })]).outcomes).toEqual(["stored"]);
  });

  it("accepts only VerifiedEvent", () => {
    const plain: NostrEvent = { ...ev({}) };
    // @ts-expect-error a NostrEvent that did not come from verification is not a VerifiedEvent
    expect(() => apply(EMPTY_STATE, plain, NOW)).not.toThrow();
  });
});

describe("replaceable and addressable events (ST-1, ST-4)", () => {
  const v1 = ev({ kind: 0, created_at: 100, content: "v1" });
  const v2 = ev({ kind: 0, created_at: 200, content: "v2" });

  it("ST-1: returns only the version with the greater created_at", () => {
    expect(run([v1, v2]).outcomes).toEqual(["stored", "stored"]);
    expect(idsOf(run([v1, v2]).state, [{ kinds: [0] }])).toEqual([v2.id]);
  });

  it("ST-1: keeps an older version that arrives later as history", () => {
    const { state, outcomes } = run([v2, v1]);
    expect(outcomes).toEqual(["stored", "stored-as-history"]);
    expect(idsOf(state, [{ kinds: [0] }])).toEqual([v2.id]);
  });

  // NIP-01: "In case of replaceable events with the same timestamp, the event with the lowest id
  // (first in lexical order) should be retained, and the other discarded."
  it("ST-1: keeps the lower id on a created_at tie in either order", () => {
    const [low, high] = lowerIdFirst(
      ev({ kind: 0, created_at: 300, content: "a" }),
      ev({ kind: 0, created_at: 300, content: "b" }),
    );
    expect(idsOf(run([low, high]).state, [{ kinds: [0] }])).toEqual([low.id]);
    expect(idsOf(run([high, low]).state, [{ kinds: [0] }])).toEqual([low.id]);
    expect(run([low, high]).outcomes).toEqual(["stored", "stored-as-history"]);
  });

  it("ST-4: returns replaced versions to a filter with ids", () => {
    const { state } = run([v1, v2]);
    expect(idsOf(state, [{ ids: [v1.id, v2.id] }])).toEqual([v2.id, v1.id]);
    expect(canonicalEvents(state)).toHaveLength(2);
  });

  it("ST-1: ignores d tags of replaceable kinds", () => {
    const withD = ev({ kind: 10002, created_at: 200, tags: [["d", "x"]] });
    const withoutD = ev({ kind: 10002, created_at: 100 });
    expect(idsOf(run([withoutD, withD]).state, [{ kinds: [10002] }])).toEqual([withD.id]);
  });

  it("ST-1: keys addressable events by pubkey, kind and d tag, with a missing d tag as empty", () => {
    const x1 = ev({ kind: 30023, created_at: 100, tags: [["d", "x"]] });
    const x2 = ev({ kind: 30023, created_at: 200, tags: [["d", "x"]] });
    const y = ev({ kind: 30023, created_at: 150, tags: [["d", "y"]] });
    const empty1 = ev({ kind: 30023, created_at: 100, tags: [["d", ""]] });
    const none = ev({ kind: 30023, created_at: 120 });
    const otherKey = ev({ kind: 30023, created_at: 300, tags: [["d", "x"]] }, KEY_B);
    const { state } = run([x1, x2, y, empty1, none, otherKey]);
    expect(new Set(idsOf(state, [{ kinds: [30023] }]))).toEqual(new Set([x2.id, y.id, none.id, otherKey.id]));
  });

  it("uses the first d tag of an addressable event", () => {
    const first = ev({
      kind: 30023,
      created_at: 100,
      tags: [
        ["d", "x"],
        ["d", "y"],
      ],
    });
    const later = ev({ kind: 30023, created_at: 200, tags: [["d", "x"]] });
    expect(idsOf(run([first, later]).state, [{ kinds: [30023] }])).toEqual([later.id]);
  });
});

describe("deletion requests (NIP-09, WR-4, ST-2)", () => {
  const note = ev({ kind: 1, content: "to delete" });
  const deleteNote = ev({ kind: 5, created_at: 200, tags: [["e", note.id]] });
  const foreignDelete = ev({ kind: 5, created_at: 200, tags: [["e", note.id]] }, KEY_B);

  it("deletes a referenced event of the same pubkey and keeps the request", () => {
    const { state, outcomes } = run([note, deleteNote]);
    expect(outcomes).toEqual(["stored", "stored"]);
    expect(idsOf(state)).toEqual([deleteNote.id]);
    expect(idsOf(state, [{ ids: [note.id] }])).toEqual([]);
  });

  // NIP-09: "Relays SHOULD delete or stop publishing any referenced events that have an identical
  // `pubkey` as the deletion request."
  it("WR-4: ignores a deletion request from another pubkey, in either order", () => {
    expect(idsOf(run([note, foreignDelete]).state, [{ kinds: [1] }])).toEqual([note.id]);
    const { state, outcomes } = run([foreignDelete, note]);
    expect(outcomes).toEqual(["stored", "stored"]);
    expect(idsOf(state, [{ kinds: [1] }])).toEqual([note.id]);
  });

  it("ST-2: rejects a target that arrives after its deletion request", () => {
    const { state, outcomes } = run([deleteNote, note]);
    expect(outcomes).toEqual(["stored", "rejected-deleted"]);
    expect(idsOf(state)).toEqual([deleteNote.id]);
  });

  it("ST-2: rejects a deleted id submitted again", () => {
    expect(run([note, deleteNote, note]).outcomes).toEqual(["stored", "stored", "rejected-deleted"]);
  });

  // NIP-09: "Publishing a deletion request event against a deletion request has no effect."
  it("ST-2: a deletion of a deletion request has no effect", () => {
    const undo = ev({ kind: 5, created_at: 300, tags: [["e", deleteNote.id]] });
    for (const order of [
      [note, deleteNote, undo],
      [undo, deleteNote, note],
    ]) {
      const { state } = run(order);
      expect(new Set(idsOf(state))).toEqual(new Set([deleteNote.id, undo.id]));
    }
  });

  it("makes the previous version current when the current one is deleted by id", () => {
    const v1 = ev({ kind: 0, created_at: 100 });
    const v2 = ev({ kind: 0, created_at: 200 });
    const deleteV2 = ev({ kind: 5, created_at: 300, tags: [["e", v2.id]] });
    expect(idsOf(run([v1, v2, deleteV2]).state, [{ kinds: [0] }])).toEqual([v1.id]);
  });

  describe("a tags", () => {
    const old = ev({ kind: 30023, created_at: 100, tags: [["d", "x:y"]] });
    const current = ev({ kind: 30023, created_at: 150, tags: [["d", "x:y"]] });
    const deleteAddress = ev({ kind: 5, created_at: 120, tags: [["a", `30023:${A}:x:y`]] });

    // NIP-09: "relays SHOULD delete all versions of the replaceable event up to the `created_at`
    // timestamp of the deletion request event."
    it("ST-2: deletes versions up to the request's created_at only", () => {
      const { state } = run([old, current, deleteAddress]);
      expect(idsOf(state, [{ kinds: [30023] }])).toEqual([current.id]);
      expect(idsOf(state, [{ ids: [old.id, current.id] }])).toEqual([current.id]);
    });

    it("ST-2: rejects a version up to the request's created_at that arrives later", () => {
      const atRequest = ev({ kind: 30023, created_at: 120, tags: [["d", "x:y"]] });
      const after = ev({ kind: 30023, created_at: 121, tags: [["d", "x:y"]] });
      expect(run([deleteAddress, old, atRequest, after]).outcomes).toEqual([
        "stored",
        "rejected-deleted",
        "rejected-deleted",
        "stored",
      ]);
    });

    it("deletes replaceable versions addressed with an empty d", () => {
      const profile = ev({ kind: 0, created_at: 100 });
      const deleteProfile = ev({ kind: 5, created_at: 100, tags: [["a", `0:${A}:`]] });
      expect(idsOf(run([profile, deleteProfile]).state, [{ kinds: [0] }])).toEqual([]);
    });

    it("applies only to replaceable and addressable kinds", () => {
      const regular = ev({ kind: 1, created_at: 100 });
      const deleteRegular = ev({ kind: 5, created_at: 200, tags: [["a", `1:${A}:`]] });
      expect(idsOf(run([regular, deleteRegular]).state, [{ kinds: [1] }])).toEqual([regular.id]);
    });

    it("WR-4: ignores an address of another pubkey", () => {
      const foreign = ev({ kind: 5, created_at: 200, tags: [["a", `30023:${A}:x:y`]] }, KEY_B);
      expect(idsOf(run([foreign, old]).state, [{ kinds: [30023] }])).toEqual([old.id]);
    });
  });
});

describe("expiration (NIP-40, EV-6, ST-3)", () => {
  it("EV-6: rejects an event whose expiration has passed on receipt, with invalid:", () => {
    const expired = ev({ tags: [["expiration", String(NOW - 1)]] });
    const atNow = ev({ tags: [["expiration", String(NOW)]] });
    const { state, outcomes } = run([expired, atNow]);
    expect(outcomes).toEqual(["rejected-expired", "rejected-expired"]);
    expect(canonicalEvents(state)).toEqual([]);
    expect(toOkResponse("rejected-expired")).toMatchObject({
      accepted: false,
      message: expect.stringMatching(/^invalid: /),
    });
  });

  it("ST-3: stops serving an event once it expires, even by id", () => {
    const expiring = ev({ tags: [["expiration", String(NOW + 10)]] });
    const { state } = run([expiring]);
    expect(idsOf(state, [{}], NOW + 9)).toEqual([expiring.id]);
    expect(idsOf(state, [{}], NOW + 10)).toEqual([]);
    expect(idsOf(state, [{ ids: [expiring.id] }], NOW + 10)).toEqual([]);
  });

  it("ignores an expiration tag that is not a decimal timestamp", () => {
    const odd = ev({ tags: [["expiration", "soon"]] });
    expect(run([odd]).outcomes).toEqual(["stored"]);
  });

  // NIP-40: "An expiration timestamp does not affect storage of ephemeral events."
  it("reports an expired ephemeral event as ephemeral", () => {
    expect(run([ev({ kind: 20001, tags: [["expiration", "1"]] })]).outcomes).toEqual(["not-stored-ephemeral"]);
  });
});

describe("query", () => {
  const events = [
    ev({ created_at: 100, content: "a" }),
    ev({ created_at: 300, content: "b" }),
    ev({ created_at: 200, content: "c" }),
    ev({ created_at: 200, content: "d" }),
    ev({ created_at: 200, content: "e" }, KEY_B),
  ];
  const { state } = run(events);

  // NIP-01: "Newer events should appear first, and in the case of ties the event with the lowest id
  // (first in lexical order) should be first."
  it("orders by created_at descending, then id ascending", () => {
    const tied = events
      .filter((event) => event.created_at === 200)
      .map((event) => event.id)
      .toSorted();
    expect(idsOf(state)).toEqual([events[1]?.id, ...tied, events[0]?.id]);
  });

  it("applies limit per filter and merges filters without duplicates", () => {
    const result = idsOf(state, [{ limit: 1 }, { authors: [B] }, { authors: [B], limit: 5 }]);
    expect(result).toEqual([events[1]?.id, events[4]?.id]);
  });

  // NIP-01: "When `limit` is zero, the relay MUST NOT return stored events for that filter."
  it("returns nothing for a filter with limit 0", () => {
    expect(idsOf(state, [{ limit: 0 }])).toEqual([]);
  });

  it("caps limit at maxLimit", () => {
    expect(query(state, [filterOf({ limit: 10 })], NOW, { maxLimit: 2 })).toHaveLength(2);
  });
});

describe("canonicalEvents (ST-7)", () => {
  it("ST-7: holds exactly the seven verified fields, without unknown fields", () => {
    const signed = ev({ content: "x\u0001", tags: [["t", "a"]] });
    const verification = verifyEvent(`{"extra":1,${JSON.stringify(signed).slice(1)}`, { now: NOW });
    if (!verification.ok) throw new Error(verification.error.code);
    const [json] = canonicalEvents(run([verification.event]).state);
    expect(Object.keys(JSON.parse(json ?? "null"))).toEqual([
      "id",
      "pubkey",
      "created_at",
      "kind",
      "tags",
      "content",
      "sig",
    ]);
    expect(JSON.parse(json ?? "null")).toEqual(signed);
    expect(verifyEvent(json ?? "", { now: NOW })).toMatchObject({ ok: true, event: signed });
  });
});

describe("toOkResponse", () => {
  it.each<[ApplyOutcome, boolean, RegExp]>([
    ["stored", true, /^$/],
    ["stored-as-history", true, /^$/],
    ["duplicate", true, /^duplicate: /],
    ["rejected-deleted", false, /^blocked: /],
    ["rejected-expired", false, /^invalid: /],
    ["not-stored-ephemeral", true, /^$/],
  ])("maps %s", (outcome, accepted, message) => {
    expect(toOkResponse(outcome)).toEqual({ accepted, message: expect.stringMatching(message) });
  });
});

describe("properties", () => {
  // A fixed pool of signed events: signing inside every run would be slow.
  const note = ev({ kind: 1, created_at: 100, content: "note" });
  const pool: VerifiedEvent[] = [
    note,
    ev({ kind: 1, created_at: 110, tags: [["t", "x"]] }, KEY_B),
    ev({ kind: 45, created_at: 105 }),
    ev({ kind: 0, created_at: 100, content: "p1" }),
    ev({ kind: 0, created_at: 200, content: "p2" }),
    ev({ kind: 0, created_at: 200, content: "p3" }),
    ev({ kind: 0, created_at: 250 }, KEY_B),
    ev({ kind: 30023, created_at: 100, tags: d("x") }),
    ev({ kind: 30023, created_at: 150, tags: d("x") }),
    ev({
      kind: 30023,
      created_at: 150,
      tags: [
        ["d", "x"],
        ["t", "y"],
      ],
    }),
    ev({ kind: 30023, created_at: 120, tags: d("y") }),
    ev({ kind: 30023, created_at: 130 }),
    ev({ kind: 5, created_at: 300, tags: [["e", note.id]] }),
    ev({ kind: 5, created_at: 300, tags: [["e", note.id]] }, KEY_B),
    ev({ kind: 5, created_at: 120, tags: [["a", `30023:${A}:x`]] }),
    ev({ kind: 5, created_at: 400, tags: [["a", `0:${A}:`]] }, KEY_B),
    ev({ kind: 1, created_at: 100, tags: [["expiration", String(NOW - 1)]] }),
    ev({ kind: 1, created_at: 100, tags: [["expiration", String(NOW + 50)]] }),
    ev({ kind: 20001, created_at: 100 }),
  ];
  const deleteOfDelete = ev({ kind: 5, created_at: 500, tags: [["e", pool[12]?.id ?? ""]] });
  pool.push(deleteOfDelete);

  const queryFilters: unknown[][] = [
    [{}],
    [{ ids: pool.map((event) => event.id) }],
    [{ kinds: [0, 30023] }],
    [{ authors: [B] }, { "#t": ["x", "y"] }],
    [{ since: 120, until: 200, limit: 3 }],
  ];

  function observe(events: readonly VerifiedEvent[]) {
    const { state } = run(events);
    return {
      stored: canonicalEvents(state),
      queries: [NOW, NOW + 50].flatMap((now) => queryFilters.map((filters) => idsOf(state, filters, now))),
    };
  }

  it("ST-1, ST-2: reaches the same state whatever the arrival order, deletions first or last", () => {
    fc.assert(
      fc.property(fc.shuffledSubarray(pool), (events) => {
        const inPoolOrder = pool.filter((event) => events.includes(event));
        expect(observe(events)).toEqual(observe(inPoolOrder));
      }),
    );
  });

  it("ST-1: is unaffected by resubmissions", () => {
    fc.assert(
      fc.property(fc.array(fc.constantFrom(...pool), { maxLength: 40 }), (events) => {
        const firstSeen = events.filter((event, index) => events.indexOf(event) === index);
        expect(observe(events)).toEqual(observe(firstSeen));
      }),
    );
  });

  it("ST-1: resolves a created_at tie to the lower id in any order", () => {
    fc.assert(
      fc.property(
        fc.uniqueArray(fc.string({ maxLength: 4 }), { minLength: 2, maxLength: 4 }),
        fc.boolean(),
        (contents, reverse) => {
          const versions = contents.map((content) => ev({ kind: 30000, created_at: 500, content, tags: d("tie") }));
          const lowest = versions.map((event) => event.id).toSorted()[0];
          const order = reverse ? versions.toReversed() : versions;
          expect(idsOf(run(order).state, [{ kinds: [30000] }])).toEqual([lowest]);
        },
      ),
      { numRuns: 20 },
    );
  });

  it("returns only matching events, ordered, within each filter's limit", () => {
    const { state } = run(pool);
    const filterArbitrary = fc.record(
      {
        kinds: fc.subarray([0, 1, 5, 45, 30023]),
        authors: fc.subarray([A, B]),
        since: fc.integer({ min: 0, max: 400 }),
        until: fc.integer({ min: 0, max: 600 }),
        limit: fc.integer({ min: 0, max: 30 }),
        "#t": fc.subarray(["x", "y", "z"]),
      },
      { requiredKeys: [] },
    );
    fc.assert(
      fc.property(
        fc.array(filterArbitrary, { minLength: 1, maxLength: 3 }),
        fc.integer({ min: NOW, max: NOW + 60 }),
        (values, now) => {
          const filters = values.map(filterOf);
          const result = query(state, filters, now);
          for (const event of result) {
            expect(matchesAnyFilter(event, filters)).toBe(true);
          }
          for (let i = 1; i < result.length; i++) {
            const [prev, next] = [result[i - 1], result[i]];
            if (prev === undefined || next === undefined) continue;
            expect(
              prev.created_at > next.created_at || (prev.created_at === next.created_at && prev.id < next.id),
            ).toBe(true);
          }
          expect(new Set(result.map((event) => event.id)).size).toBe(result.length);
          const total = filters.reduce((sum, filter) => sum + (filter.limit ?? 500), 0);
          expect(result.length).toBeLessThanOrEqual(total);
        },
      ),
    );
  });
});
