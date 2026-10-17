import {
  canonicalEventJson,
  referenceModel,
  verifyEvent,
  type Filter,
  type NostrEvent,
  type VerifiedEvent,
} from "@zenith/core";
import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import * as fc from "fast-check";
import { describe, expect, it } from "vitest";
import { EventStore } from "./store.ts";
import { filterOf, publicKeyOf, signVerified, testSecretKey } from "./test-support.ts";

const KEY_A = testSecretKey("A");
const KEY_B = testSecretKey("B");
const A = publicKeyOf(KEY_A);
const B = publicKeyOf(KEY_B);
const NOW = 1_000;

function ev(template: Partial<NostrEvent>, key: Uint8Array = KEY_A): VerifiedEvent {
  return signVerified({ created_at: 100, ...template }, key);
}

/** Runs `callback` inside a new Vault DO with a store opened on its SQLite storage. */
async function withStore<T>(callback: (store: EventStore, storage: DurableObjectStorage) => T): Promise<T> {
  const stub = env.VAULT.get(env.VAULT.newUniqueId());
  return runInDurableObject(stub, (_instance, state) => callback(new EventStore(state.storage), state.storage));
}

/**
 * Applies the writes to the store and to the reference model, checking each outcome, and returns the model state.
 */
function applyBoth(store: EventStore, events: readonly VerifiedEvent[], now = NOW): referenceModel.ModelState {
  let model = referenceModel.EMPTY_STATE;
  for (const event of events) {
    const expected = referenceModel.apply(model, event, now);
    model = expected.state;
    expect(store.apply(event, now)).toBe(expected.outcome);
  }
  return model;
}

function expectSameQuery(
  store: EventStore,
  model: referenceModel.ModelState,
  filters: readonly Filter[],
  now = NOW,
): string[] {
  const result = store.query(filters, now);
  expect(result).toEqual(referenceModel.query(model, filters, now).map(canonicalEventJson));
  return result;
}

function idsOf(json: readonly string[]): string[] {
  return json.map((text) => {
    const value: unknown = JSON.parse(text);
    return typeof value === "object" && value !== null && "id" in value ? String(value.id) : "";
  });
}

function lowerIdFirst(a: VerifiedEvent, b: VerifiedEvent): [VerifiedEvent, VerifiedEvent] {
  return a.id < b.id ? [a, b] : [b, a];
}

describe("apply and query on SQLite, against the reference model", () => {
  it("WR-5: does not store ephemeral kinds, 22242 included", async () => {
    await withStore((store) => {
      applyBoth(store, [ev({ kind: 20000 }), ev({ kind: 22242 }), ev({ kind: 29999 })]);
      expect(store.canonicalEvents()).toEqual([]);
    });
  });

  it("EV-6: rejects an event already expired on receipt, an expiration equal to now included", async () => {
    await withStore((store) => {
      const outcomes = [ev({ tags: [["expiration", String(NOW - 1)]] }), ev({ tags: [["expiration", String(NOW)]] })];
      applyBoth(store, outcomes);
      expect(store.canonicalEvents()).toEqual([]);
    });
  });

  it("ST-3: stops serving an event once it expires, even by id", async () => {
    await withStore((store) => {
      const expiring = ev({ tags: [["expiration", String(NOW + 10)]] });
      const model = applyBoth(store, [expiring]);
      expect(expectSameQuery(store, model, [filterOf({})], NOW + 9)).toHaveLength(1);
      expect(expectSameQuery(store, model, [filterOf({})], NOW + 10)).toEqual([]);
      expect(expectSameQuery(store, model, [filterOf({ ids: [expiring.id] })], NOW + 10)).toEqual([]);
    });
  });

  it("ST-1, ST-4: keeps the lower id on a created_at tie and returns the other only by ids", async () => {
    const [low, high] = lowerIdFirst(
      ev({ kind: 0, created_at: 300, content: "a" }),
      ev({ kind: 0, created_at: 300, content: "b" }),
    );
    for (const order of [
      [low, high],
      [high, low],
    ]) {
      await withStore((store) => {
        const model = applyBoth(store, order);
        expect(idsOf(expectSameQuery(store, model, [filterOf({ kinds: [0] })]))).toEqual([low.id]);
        expect(idsOf(expectSameQuery(store, model, [filterOf({ ids: [low.id, high.id] })]))).toEqual([low.id, high.id]);
      });
    }
  });

  it("ST-2: rejects a deleted id submitted again, and a target that arrives after its deletion", async () => {
    const note = ev({ kind: 1, content: "to delete" });
    const deletion = ev({ kind: 5, created_at: 200, tags: [["e", note.id]] });
    await withStore((store) => {
      applyBoth(store, [note, deletion, note]);
    });
    await withStore((store) => {
      applyBoth(store, [deletion, note]);
      expect(store.canonicalEvents()).toEqual([canonicalEventJson(deletion)]);
    });
  });

  it("WR-4: ignores deletion requests of another pubkey, by e and by a tag, in either order", async () => {
    const note = ev({ kind: 1 });
    const article = ev({ kind: 30023, tags: [["d", "x"]] });
    const foreign = ev(
      {
        kind: 5,
        created_at: 200,
        tags: [
          ["e", note.id],
          ["a", `30023:${A}:x`],
        ],
      },
      KEY_B,
    );
    for (const order of [
      [note, article, foreign],
      [foreign, note, article],
    ]) {
      await withStore((store) => {
        const model = applyBoth(store, order);
        expect(expectSameQuery(store, model, [filterOf({ authors: [A] })])).toHaveLength(2);
      });
    }
  });

  it("ST-2: an a-tag deletion applies up to its created_at only, in either order", async () => {
    const atRequest = ev({ kind: 30023, created_at: 120, tags: [["d", "x:y"]] });
    const after = ev({ kind: 30023, created_at: 121, tags: [["d", "x:y"]] });
    const deletion = ev({ kind: 5, created_at: 120, tags: [["a", `30023:${A}:x:y`]] });
    for (const order of [
      [atRequest, after, deletion],
      [deletion, atRequest, after],
    ]) {
      await withStore((store) => {
        const model = applyBoth(store, order);
        expect(idsOf(expectSameQuery(store, model, [filterOf({ kinds: [30023] })]))).toEqual([after.id]);
      });
    }
  });

  it("makes the previous version current when the current one is deleted by id", async () => {
    const v1 = ev({ kind: 0, created_at: 100 });
    const v2 = ev({ kind: 0, created_at: 200 });
    await withStore((store) => {
      const model = applyBoth(store, [v1, v2, ev({ kind: 5, created_at: 300, tags: [["e", v2.id]] })]);
      expect(idsOf(expectSameQuery(store, model, [filterOf({ kinds: [0] })]))).toEqual([v1.id]);
    });
  });

  it("ST-7: stores the verified fields only, so the stored JSON parses back to the verified event", async () => {
    const signed = ev({ content: "x\u0001", tags: [["t", "a"]] });
    const received = `{"extra":1,"content":"other",${JSON.stringify(signed).slice(1)}`;
    const verification = verifyEvent(received, { now: NOW });
    if (!verification.ok) throw new Error(verification.error.code);
    await withStore((store) => {
      applyBoth(store, [verification.event]);
      const [json] = store.canonicalEvents();
      expect(json).toBe(canonicalEventJson(signed));
      expect(JSON.parse(json ?? "null")).toEqual(signed);
      expect(store.query([filterOf({})], NOW)).toEqual([json]);
    });
  });
});

describe("RES-2: values are bound, never spliced", () => {
  const INJECTIONS = ["' OR 1=1 --", '" OR ""="', "x'); DROP TABLE events; --", "%", "_", "\u0000", "?"];

  it("RES-2: injection strings in ids, #e and #t return no events and raise no error", async () => {
    await withStore((store) => {
      const note = ev({ tags: [["t", "a"]] });
      const model = applyBoth(store, [note]);
      // parseFilter refuses non-hex ids and #e values, so these filters are built directly.
      const filters: Filter[] = [
        { ids: new Set(INJECTIONS), tags: new Map() },
        { tags: new Map([["e", new Set(INJECTIONS)]]) },
        filterOf({ "#t": INJECTIONS }),
        filterOf({ "#t": INJECTIONS, authors: [A], kinds: [1] }),
      ];
      for (const filter of filters) expect(expectSameQuery(store, model, [filter])).toEqual([]);
      expect(store.canonicalEvents()).toEqual([canonicalEventJson(note)]);
    });
  });

  it("RES-2: stores and finds tag values that look like SQL", async () => {
    await withStore((store) => {
      const events = INJECTIONS.map((value, index) => ev({ kind: 30000, created_at: index, tags: [["d", value]] }));
      const model = applyBoth(store, events);
      for (const value of INJECTIONS) {
        expect(expectSameQuery(store, model, [filterOf({ "#d": [value] })])).toHaveLength(1);
      }
      expect(expectSameQuery(store, model, [filterOf({ "#d": INJECTIONS })])).toHaveLength(INJECTIONS.length);
    });
  });
});

describe("RES-2: lists longer than the bound parameter limit run in chunks", () => {
  // 100 keys, so that an authors list longer than 90 matters.
  const keys = Array.from({ length: 100 }, (_, index) => testSecretKey(`chunk ${index}`));
  // Single letters other than e and p (hex only) and t (used above).
  const letters = "abcdfghijklmnoqrsuv".split("");
  const events = keys.flatMap((key, index) => [
    ev(
      {
        kind: 1,
        created_at: index % 7,
        // The last letter differs from the others, so a scan that skipped the lists it could not bind would show.
        tags: [
          ["t", `t${index % 13}`],
          ...letters.map((name) => [name, name === "v" ? `w${index % 2}` : `v${index % 5}`]),
        ],
      },
      key,
    ),
    ev({ kind: 30000 + (index % 3), created_at: 50 + (index % 5), tags: [["d", "x"]] }, key),
  ]);
  const authors = keys.map(publicKeyOf);
  const unknownIds = Array.from({ length: 1000 }, (_, index) => index.toString(16).padStart(64, "0"));
  const manyKinds = [1, ...Array.from({ length: 117 }, (_, index) => 100 + index), 30001, 30002];
  const everyLetter = Object.fromEntries(
    letters.map((name) => [
      `#${name}`,
      // #v, the only list that narrows, is the longest, so the scan leaves it to the check on each row.
      name === "v" ? [...unknownIds.slice(0, 46), "w1"] : [...unknownIds.slice(0, 40), "v0", "v1", "v2", "v3", "v4"],
    ]),
  );

  const cases: [string, unknown][] = [
    ["1000 ids", { ids: [...unknownIds.slice(0, 1000 - events.length), ...events.map((event) => event.id)] }],
    ["100 authors", { authors }],
    ["100 authors and 400 ids", { authors, ids: [...unknownIds.slice(0, 200), ...events.map((e) => e.id)] }],
    [
      "100 authors, kinds and 100 #t values",
      {
        authors,
        kinds: [1, 30000],
        "#t": unknownIds
          .slice(0, 87)
          .concat(["t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "t10", "t11", "t12", "t0"]),
      },
    ],
    // 20 tag lists cannot be split into few enough queries, so this one is answered by a scan.
    [
      "20 tag lists",
      Object.fromEntries([
        ...letters.map((name) => [
          `#${name}`,
          [...unknownIds.slice(0, 40), ...(name === "v" ? ["w1"] : ["v1", "v2", "v3"])],
        ]),
        ["#t", ["t3", "t4", "t5"]],
      ]),
    ],
    // 120 valid kinds, with the stored ones at both ends, so that they fall in different chunks.
    ["120 kinds", { kinds: manyKinds }],
    ["120 kinds with a limit", { kinds: manyKinds, limit: 25 }],
    // The lists the scan can bind match all 100 kind 1 events, more than one page; only #v narrows them.
    ["19 tag lists over several scan pages", everyLetter],
    ["19 tag lists over several scan pages, with a limit", { ...everyLetter, limit: 30 }],
    [
      "1000 ids with a limit",
      { ids: [...unknownIds.slice(0, 1000 - events.length), ...events.map((event) => event.id)], limit: 7 },
    ],
  ];

  it.each(cases)("RES-2: answers %s like the reference model", async (_name, value) => {
    await withStore((store) => {
      const model = applyBoth(store, events);
      const result = expectSameQuery(store, model, [filterOf(value)]);
      expect(result.length).toBeGreaterThan(0);
    });
  });
});

describe("properties", () => {
  // A fixed pool of signed events, the same kinds of cases as the reference model's properties.
  const note = ev({ kind: 1, created_at: 100, content: "note" });
  const profile = ev({ kind: 0, created_at: 200, content: "p2" });
  const article = ev({ kind: 30023, created_at: 150, tags: [["d", "x"]] });
  const deleteNote = ev({ kind: 5, created_at: 300, tags: [["e", note.id]] });
  const pool: VerifiedEvent[] = [
    note,
    ev({ kind: 1, created_at: 110, tags: [["t", "x"]] }, KEY_B),
    ev({ kind: 45, created_at: 105 }),
    // Several values of one tag name, one of them twice: each is indexed.
    ev({
      kind: 1,
      created_at: 115,
      tags: [
        ["t", "y"],
        ["t", "x"],
        ["t", "y"],
      ],
    }),
    ev({ kind: 0, created_at: 100, content: "p1" }),
    profile,
    ev({ kind: 0, created_at: 200, content: "p3" }),
    ev({ kind: 0, created_at: 250 }, KEY_B),
    ev({ kind: 30023, created_at: 100, tags: [["d", "x"]] }),
    article,
    ev({
      kind: 30023,
      created_at: 150,
      tags: [
        ["d", "x"],
        ["t", "y"],
      ],
    }),
    ev({ kind: 30023, created_at: 120, tags: [["d", "y"]] }),
    ev({ kind: 30023, created_at: 130 }),
    ev({ kind: 30023, created_at: 140, tags: [["d"], ["d", "y"], ["t", "\u0000'"]] }),
    deleteNote,
    ev({ kind: 5, created_at: 300, tags: [["e", note.id]] }, KEY_B),
    ev({ kind: 5, created_at: 120, tags: [["a", `30023:${A}:x`]] }),
    ev({ kind: 5, created_at: 400, tags: [["a", `0:${A}:`]] }, KEY_B),
    ev({
      kind: 5,
      created_at: 400,
      tags: [
        ["a", `30023:${A}:`],
        ["a", `030023:${A}:y`],
      ],
    }),
    ev({ kind: 1, created_at: 100, tags: [["expiration", String(NOW - 1)]] }),
    ev({ kind: 1, created_at: 100, tags: [["expiration", String(NOW + 50)]] }),
    ev({ kind: 0, created_at: 300, tags: [["expiration", String(NOW + 50)]] }),
    ev({
      kind: 1,
      created_at: 100,
      tags: [
        ["expiration", "soon"],
        ["expiration", "1"],
      ],
    }),
    ev({ kind: 20001, created_at: 100 }),
    // A deletion of a deletion has no effect.
    ev({ kind: 5, created_at: 500, tags: [["e", deleteNote.id]] }),
    // Deleting a version by id can make an older one current again.
    ev({
      kind: 5,
      created_at: 350,
      tags: [
        ["e", profile.id],
        ["e", article.id],
      ],
    }),
  ];

  const fixedFilters: Filter[][] = [
    [{}],
    [{ ids: pool.map((event) => event.id) }],
    [{ kinds: [0, 30023] }],
    [{ authors: [B] }, { "#t": ["x", "y"] }],
    [{ "#t": ["x"] }],
    [{ since: 120, until: 200, limit: 3 }],
    [{ "#d": ["", "x", "y"] }, { "#e": [note.id] }],
  ].map((filters) => filters.map(filterOf));

  const filterArbitrary = fc.record(
    {
      ids: fc.subarray(pool.map((event) => event.id)),
      kinds: fc.subarray([0, 1, 5, 45, 30023]),
      authors: fc.subarray([A, B]),
      since: fc.integer({ min: 0, max: 400 }),
      until: fc.integer({ min: 0, max: 600 }),
      limit: fc.integer({ min: 0, max: 30 }),
      "#t": fc.subarray(["x", "y", "z", "\u0000'"]),
      "#d": fc.subarray(["", "x", "y"]),
    },
    { requiredKeys: [] },
  );

  it("ST-1, ST-2, ST-3, ST-4, ST-7, EV-6, WR-4, WR-5: gives the reference model's outcomes, stored events and REQ results", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.oneof(fc.shuffledSubarray(pool), fc.array(fc.constantFrom(...pool), { maxLength: 40 })),
        fc.array(filterArbitrary, { minLength: 1, maxLength: 3 }),
        async (events, generated) => {
          await withStore((store) => {
            const model = applyBoth(store, events);
            expect(store.canonicalEvents()).toEqual(referenceModel.canonicalEvents(model));
            for (const now of [NOW, NOW + 50]) {
              for (const filters of [...fixedFilters, generated.map(filterOf)]) {
                expectSameQuery(store, model, filters, now);
              }
            }
          });
        },
      ),
      { numRuns: 150 },
    );
  });
});
