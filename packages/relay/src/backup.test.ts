import { canonicalEventJson, referenceModel, type Filter, type NostrEvent, type VerifiedEvent } from "@zenith/core";
import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import * as fc from "fast-check";
import { describe, expect, it } from "vitest";
import { mergeAllowlists, type AllowlistState } from "./allowlist.ts";

import { formatAllowlist, parseAllowlist } from "./backup.ts";
import { EventStore, type Backup } from "./store.ts";
import { filterOf, openStore, publicKeyOf, signVerified, testConfig, testSecretKey } from "./test-support.ts";

const KEY_OWNER = testSecretKey("owner");
const KEY_B = testSecretKey("B");
const KEY_C = testSecretKey("C");
const KEY_D = testSecretKey("D");
const KEY_E = testSecretKey("E");
const OWNER = publicKeyOf(KEY_OWNER);
const B = publicKeyOf(KEY_B);
const C = publicKeyOf(KEY_C);
const D = publicKeyOf(KEY_D);
const E = publicKeyOf(KEY_E);
const NOW = 1_000;
const CONFIG = testConfig(OWNER);

function ev(template: Partial<NostrEvent>, key: Uint8Array = KEY_OWNER): VerifiedEvent {
  return signVerified({ created_at: 100, ...template }, key);
}

/** Copies a backup into plain values, as a backup file would hold it. */
function materialize(backup: Backup): { events: string[]; allowlist: string } {
  return { events: [...backup.events], allowlist: backup.allowlist };
}

/** Runs `callback` inside a new Vault DO, on its SQLite storage. */
async function withVault<T>(callback: (storage: DurableObjectStorage) => T): Promise<T> {
  const stub = env.VAULT.get(env.VAULT.newUniqueId());
  return runInDurableObject(stub, (_instance, state) => callback(state.storage));
}

/** What a store holds and answers: its backup, its stored events, its allowlist and its REQ results at two times. */
function observe(store: EventStore, filterSets: readonly Filter[][]) {
  return {
    backup: materialize(store.export()),
    stored: store.canonicalEvents(),
    keys: store.listKeys(),
    queries: [NOW, NOW + 50].flatMap((now) => filterSets.map((filters) => store.query(filters, now))),
  };
}

/** The merged allowlist; fails the test when the merge refuses. */
function merged(current: AllowlistState, backup: AllowlistState, config = CONFIG): AllowlistState {
  const result = mergeAllowlists(current, backup, config);
  if (!result.ok) throw new Error(result.code);
  return result.state;
}

function listed(pubkey: string, role: "importer" | "retired", kinds: number[], addedAt = 0) {
  return { pubkey, role, kinds, addedAt } as const;
}

// ST-7: the export gives the stored canonical JSON as it is, and a restore stores it again in canonical form.
describe("export (DATA-5)", () => {
  it("DATA-5: exports every stored event as canonical JSONL sorted by id, and the allowlist as JSON", async () => {
    await withVault((storage) => {
      const store = openStore(storage, OWNER, [[B, [1, 5]]]);
      const v1 = ev({ kind: 0, created_at: 100 });
      const v2 = ev({ kind: 0, created_at: 200 });
      for (const event of [v1, v2, ev({ kind: 1 }, KEY_B)]) store.apply(event, NOW);
      store.retireKey(B);
      const backup = materialize(store.export());
      expect(backup.events).toEqual(store.canonicalEvents());
      expect(backup.events).toHaveLength(3);
      expect(backup.events.every((line) => !line.includes("\n"))).toBe(true);
      expect(JSON.parse(backup.allowlist)).toEqual({
        version: 1,
        keys: [
          { pubkey: OWNER, role: "owner", added_at: 0 },
          { pubkey: B, role: "retired", kinds: [1, 5], added_at: 0 },
        ].toSorted((a, b) => (a.pubkey < b.pubkey ? -1 : 1)),
        revoked: [],
      });
      expect(parseAllowlist(backup.allowlist)).toEqual({ ok: true, state: store.listKeys() });
    });
  });

  it("DATA-5, ST-6: a backup is fixed when export returns; later keys and writes do not join it", async () => {
    await withVault((storage) => {
      const store = openStore(storage, OWNER);
      store.apply(ev({ kind: 1, content: "before" }), NOW);
      const backup = store.export();
      const copy = materialize(backup);
      expect(store.addKey(B, { role: "importer", kinds: [1] }, NOW)).toEqual({ ok: true });
      expect(store.apply(ev({ kind: 1, content: "after" }, KEY_B), NOW)).toMatchObject({ ok: true, outcome: "stored" });
      expect(store.apply(ev({ kind: 1, content: "after" }), NOW)).toMatchObject({ ok: true, outcome: "stored" });
      expect(materialize(backup)).toEqual(copy);
      expect(backup.events).toHaveLength(1);
      const parsed = parseAllowlist(backup.allowlist);
      expect(parsed.ok && parsed.state.keys.map((key) => key.pubkey)).toEqual([OWNER]);
    });
  });

  it.each([
    ["not JSON", "{"],
    ["another version", JSON.stringify({ version: 2, keys: [], revoked: [] })],
    [
      "an unknown role",
      JSON.stringify({ version: 1, keys: [{ pubkey: B, role: "admin", kinds: [1], added_at: 0 }], revoked: [] }),
    ],
    [
      "an importer without kinds",
      JSON.stringify({ version: 1, keys: [{ pubkey: B, role: "importer", kinds: [], added_at: 0 }], revoked: [] }),
    ],
    [
      "kind 62",
      JSON.stringify({ version: 1, keys: [{ pubkey: B, role: "importer", kinds: [62], added_at: 0 }], revoked: [] }),
    ],
    [
      "a key listed twice",
      JSON.stringify({
        version: 1,
        keys: [listed(B, "importer", [1]), listed(B, "retired", [1])].map(({ addedAt, ...rest }) => ({
          ...rest,
          added_at: addedAt,
        })),
        revoked: [],
      }),
    ],
    [
      "a key both listed and revoked",
      JSON.stringify({
        version: 1,
        keys: [{ pubkey: B, role: "importer", kinds: [1], added_at: 0 }],
        revoked: [{ pubkey: B, revoked_at: 1 }],
      }),
    ],
    [
      "two owners",
      JSON.stringify({
        version: 1,
        keys: [
          { pubkey: B, role: "owner", added_at: 0 },
          { pubkey: C, role: "owner", added_at: 0 },
        ],
        revoked: [],
      }),
    ],
  ])("refuses an allowlist with %s", (_name, text) => {
    expect(parseAllowlist(text)).toEqual({ ok: false, code: "bad-allowlist" });
  });
});

describe("restore (ST-6)", () => {
  it("ST-6: rebuilds the same events, allowlist and REQ results in an empty store", async () => {
    const note = ev({ kind: 1 }, KEY_B);
    const filters = [filterOf({})];
    const source = await withVault((storage) => {
      const store = openStore(storage, OWNER, [[B, [0, 1, 5]]]);
      for (const event of [
        note,
        ev({ kind: 0, created_at: 100 }),
        ev({ kind: 0, created_at: 200 }),
        ev({ kind: 5, created_at: 300, tags: [["e", note.id]] }, KEY_B),
        ev({ kind: 1, tags: [["expiration", String(NOW + 10)]] }),
      ]) {
        store.apply(event, NOW);
      }
      return observe(store, [filters]);
    });
    await withVault((storage) => {
      const target = openStore(storage, OWNER);
      expect(target.restore(source.backup)).toEqual({ ok: true, events: 4, allowlistChanged: true });
      expect(observe(target, [filters])).toEqual(source);
    });
  });

  it("ST-6: restores events that the write path refuses: other keys, expired, protected, kind 5 and kind 62", async () => {
    const note = ev({ kind: 1 }, KEY_D);
    const events = [
      note,
      ev({ kind: 1, tags: [["expiration", "1"]] }),
      ev({ kind: 1, tags: [["-"]], content: "protected" }),
      ev({ kind: 5, created_at: 200, tags: [["e", note.id]] }, KEY_D),
      ev({ kind: 30023, tags: [["d", "x"]] }, KEY_E),
      ev({ kind: 62, tags: [["relay", "ALL_RELAYS"]] }, KEY_E),
      ev({ kind: 20001 }),
    ];
    await withVault((storage) => {
      const store = openStore(storage, OWNER);
      const result = store.restore({
        events: events.map(canonicalEventJson),
        allowlist: formatAllowlist(store.listKeys()),
      });
      expect(result).toEqual({ ok: true, events: 6, allowlistChanged: false });
      // The same events stored with the usual semantics, none expired on receipt: the model at a time before every
      // expiration.
      let model = referenceModel.EMPTY_STATE;
      for (const event of events) model = referenceModel.apply(model, event, -1).state;
      expect(store.canonicalEvents()).toEqual(referenceModel.canonicalEvents(model));
    });
  });

  it("ST-6, ST-2: rebuilds the deletion index, so deleted ids and versions stay deleted", async () => {
    const note = ev({ kind: 1, content: "deleted by id" });
    const atDeletion = ev({ kind: 30023, created_at: 120, tags: [["d", "x"]] });
    const deleteNote = ev({ kind: 5, created_at: 200, tags: [["e", note.id]] });
    const deleteAddress = ev({ kind: 5, created_at: 120, tags: [["a", `30023:${OWNER}:x`]] });
    const backup = await withVault((storage) => {
      const source = openStore(storage, OWNER);
      for (const event of [note, atDeletion, deleteNote, deleteAddress]) source.apply(event, NOW);
      return materialize(source.export());
    });
    // The backup holds only the deletion requests: the deleted events are not in it.
    expect(backup.events).toEqual([canonicalEventJson(deleteNote), canonicalEventJson(deleteAddress)].toSorted());
    await withVault((storage) => {
      const target = openStore(storage, OWNER);
      expect(target.restore(backup)).toMatchObject({ ok: true, events: 2 });
      expect(target.apply(note, NOW)).toEqual({ ok: true, outcome: "rejected-deleted" });
      expect(target.apply(atDeletion, NOW)).toEqual({ ok: true, outcome: "rejected-deleted" });
      const older = ev({ kind: 30023, created_at: 100, tags: [["d", "x"]] });
      expect(target.apply(older, NOW)).toEqual({ ok: true, outcome: "rejected-deleted" });
      const after = ev({ kind: 30023, created_at: 121, tags: [["d", "x"]] });
      expect(target.apply(after, NOW)).toEqual({ ok: true, outcome: "stored" });
    });
  });

  it("ST-6: restores nothing when one event fails verification", async () => {
    const good = ev({ kind: 1 });
    const forged = { ...ev({ kind: 1, content: "x" }), content: "y" };
    await withVault((storage) => {
      const store = openStore(storage, OWNER);
      const allowlist = JSON.stringify({
        version: 1,
        keys: [{ pubkey: B, role: "importer", kinds: [1], added_at: 0 }],
        revoked: [],
      });
      for (const [line, events] of [
        [2, [canonicalEventJson(good), JSON.stringify(forged)]],
        [1, ["not json"]],
        [2, [canonicalEventJson(good), JSON.stringify({ ...good, sig: "0".repeat(128) })]],
      ] as const) {
        expect(store.restore({ events, allowlist })).toEqual({ ok: false, code: "bad-event", line });
        expect(store.canonicalEvents()).toEqual([]);
        expect(store.listKeys().keys.map((k) => k.pubkey)).toEqual([OWNER]);
      }
    });
  });

  it("ST-6: refuses a bad allowlist and a store that already holds events", async () => {
    await withVault((storage) => {
      const store = openStore(storage, OWNER);
      expect(store.restore({ events: [], allowlist: "[]" })).toEqual({ ok: false, code: "bad-allowlist" });
      store.apply(ev({ kind: 1 }), NOW);
      const backup = materialize(store.export());
      expect(store.restore(backup)).toEqual({ ok: false, code: "not-empty" });
    });
  });
});

describe("restoring the allowlist (ST-8)", () => {
  const empty: AllowlistState = { keys: [], revoked: [] };
  const owner = { pubkey: OWNER, role: "owner", addedAt: 0 } as const;

  it("ST-8: never lists a key the current allowlist revoked", () => {
    const current = { keys: [owner], revoked: [{ pubkey: B, revokedAt: 5 }] };
    const backup = { keys: [owner, listed(B, "importer", [1])], revoked: [] };
    expect(merged(current, backup, CONFIG)).toEqual(current);
  });

  it("ST-8: keeps a key the backup records as revoked out of the allowlist", () => {
    const current = { keys: [owner, listed(B, "importer", [1])], revoked: [] };
    const backup = { keys: [owner], revoked: [{ pubkey: B, revokedAt: 5 }] };
    expect(merged(current, backup, CONFIG)).toEqual({ keys: [owner], revoked: [{ pubkey: B, revokedAt: 5 }] });
  });

  it("ST-8: keeps a key retired when either side has it retired", () => {
    const retiredB = listed(B, "retired", [1]);
    const importerB = listed(B, "importer", [1]);
    expect(
      merged({ keys: [owner, retiredB], revoked: [] }, { keys: [importerB], revoked: [] }, CONFIG).keys,
    ).toContainEqual(retiredB);
    expect(
      merged({ keys: [owner, importerB], revoked: [] }, { keys: [retiredB], revoked: [] }, CONFIG).keys,
    ).toContainEqual(retiredB);
  });

  it("ST-8: never widens the kinds of a listed key", () => {
    const state = merged(
      { keys: [owner, listed(B, "importer", [1])], revoked: [] },
      { keys: [listed(B, "importer", [0, 1, 5])], revoked: [] },
      CONFIG,
    );
    expect(state.keys).toContainEqual(listed(B, "importer", [1]));
  });

  it("restores an importer the current allowlist does not have", () => {
    const state = merged(
      { keys: [owner], revoked: [] },
      { keys: [owner, listed(B, "importer", [1], 7)], revoked: [] },
      CONFIG,
    );
    expect(state.keys).toContainEqual(listed(B, "importer", [1], 7));
  });

  it("ST-8: makes no key the owner but the configured one", () => {
    const foreignOwner = { pubkey: C, role: "owner", addedAt: 3 } as const;
    expect(merged({ keys: [owner], revoked: [] }, { keys: [foreignOwner], revoked: [] })).toEqual({
      keys: [owner, listed(C, "retired", [], 3)].toSorted((a, b) => (a.pubkey < b.pubkey ? -1 : 1)),
      revoked: [],
    });
  });

  it.each([
    ["the backup revoked", { keys: [], revoked: [{ pubkey: OWNER, revokedAt: 1 }] }, "owner-revoked"],
    [
      "the backup retired",
      { keys: [{ pubkey: OWNER, role: "retired", kinds: [], addedAt: 0 }], revoked: [] },
      "owner-retired",
    ],
  ] as const)("ST-8: refuses to merge when %s the configured owner", (_name, backup, code) => {
    expect(mergeAllowlists({ keys: [owner], revoked: [] }, backup, CONFIG)).toEqual({ ok: false, code });
  });

  it("ST-8: restores nothing from a backup that revoked the configured owner", async () => {
    const backup = await withVault((storage) => {
      const source = openStore(storage, B, [[OWNER, [1]]]);
      source.apply(ev({ kind: 1 }), NOW);
      source.revokeKey(OWNER, NOW);
      return materialize(source.export());
    });
    await withVault((storage) => {
      const target = openStore(storage, OWNER);
      const before = target.listKeys();
      expect(target.restore(backup)).toEqual({ ok: false, code: "owner-revoked" });
      expect(target.canonicalEvents()).toEqual([]);
      expect(target.listKeys()).toEqual(before);
    });
  });

  it("changes nothing when restoring an empty allowlist", () => {
    expect(merged({ keys: [owner], revoked: [] }, empty, CONFIG)).toEqual({ keys: [owner], revoked: [] });
  });

  it("ST-8: a restore that includes a retired key keeps it retired and its events out of normal REQs", async () => {
    const note = ev({ kind: 1 }, KEY_B);
    const backup = await withVault((storage) => {
      const source = openStore(storage, OWNER, [[B, [1]]]);
      source.apply(note, NOW);
      source.retireKey(B);
      return materialize(source.export());
    });
    await withVault((storage) => {
      const target = openStore(storage, OWNER, [[B, [1]]]);
      expect(target.restore(backup)).toMatchObject({ ok: true, allowlistChanged: true });
      expect(target.listKeys().keys).toContainEqual(listed(B, "retired", [1]));
      expect(target.apply(ev({ kind: 1, content: "after" }, KEY_B), NOW)).toEqual({
        ok: false,
        code: "retired-key",
      });
      expect(target.query([filterOf({})], NOW)).toEqual([]);
      expect(target.query([filterOf({ ids: [note.id] })], NOW)).toEqual([canonicalEventJson(note)]);
    });
  });

  it("ST-8: a restore never lists again a key the target revoked", async () => {
    const backup = await withVault((storage) => materialize(openStore(storage, OWNER, [[B, [1]]]).export()));
    await withVault((storage) => {
      const target = openStore(storage, OWNER, [[B, [1]]]);
      target.revokeKey(B, NOW);
      expect(target.restore(backup)).toEqual({ ok: true, events: 0, allowlistChanged: false });
      expect(target.apply(ev({ kind: 1 }, KEY_B), NOW)).toEqual({ ok: false, code: "unknown-key" });
    });
  });
});

describe("properties", () => {
  const note = ev({ kind: 1, created_at: 100, content: "note" });
  const pool: VerifiedEvent[] = [
    note,
    ev({ kind: 1, created_at: 110, tags: [["t", "x"]] }, KEY_B),
    ev({ kind: 0, created_at: 100, content: "p1" }),
    ev({ kind: 0, created_at: 200, content: "p2" }),
    ev({ kind: 0, created_at: 250 }, KEY_B),
    ev({ kind: 30023, created_at: 100, tags: [["d", "x"]] }, KEY_C),
    ev({ kind: 30023, created_at: 150, tags: [["d", "x"]] }, KEY_C),
    ev({ kind: 1, created_at: 120, tags: [["-"]] }, KEY_D),
    ev({ kind: 30023, created_at: 130, tags: [["d", "y"]] }, KEY_E),
    ev({ kind: 5, created_at: 300, tags: [["e", note.id]] }),
    ev({ kind: 5, created_at: 300, tags: [["a", `30023:${C}:x`]] }, KEY_C),
    ev({ kind: 5, created_at: 300, tags: [["e", note.id]] }, KEY_D),
    ev({ kind: 1, created_at: 100, tags: [["expiration", String(NOW + 20)]] }, KEY_D),
    ev({ kind: 1, created_at: 100, tags: [["expiration", String(NOW - 1)]] }, KEY_E),
    ev({ kind: 20001, created_at: 100 }),
    ev({ kind: 62, created_at: 100 }),
  ];
  type Action =
    | { type: "write"; event: VerifiedEvent }
    | { type: "retire"; pubkey: string }
    | { type: "revoke"; pubkey: string };
  const action: fc.Arbitrary<Action> = fc.oneof(
    { weight: 4, arbitrary: fc.constantFrom(...pool).map((event): Action => ({ type: "write", event })) },
    fc.constantFrom(B, C, D, E).map((pubkey): Action => ({ type: "retire", pubkey })),
    fc.constantFrom(B, C, D, E).map((pubkey): Action => ({ type: "revoke", pubkey })),
  );
  const fixedFilters = [
    [{}],
    [{ ids: pool.map((event) => event.id) }],
    [{ kinds: [0, 30023] }, { authors: [B, D] }],
    [{ "#t": ["x"] }, { "#d": ["x", "y"] }],
    [{ since: 110, limit: 2 }],
  ].map((filters) => filters.map(filterOf));
  const filterArbitrary = fc.record(
    {
      ids: fc.subarray(pool.map((event) => event.id)),
      kinds: fc.subarray([0, 1, 5, 30023]),
      authors: fc.subarray([OWNER, B, C, D, E]),
      limit: fc.integer({ min: 0, max: 10 }),
    },
    { requiredKeys: [] },
  );

  it("ST-6, ST-8, ST-5: a restored store answers the same REQs, with retired, revoked, expired and deleted events", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(action, { maxLength: 30 }),
        fc.array(filterArbitrary, { minLength: 1, maxLength: 3 }),
        async (actions, generated) => {
          const filterSets = [...fixedFilters, generated.map(filterOf)];
          const source = await withVault((storage) => {
            const store = openStore(storage, OWNER, [
              [B, [0, 1, 5]],
              [C, [5, 30023]],
              [D, [1, 5]],
              [E, [1, 30023]],
            ]);
            for (const item of actions) {
              if (item.type === "write") store.apply(item.event, NOW);
              else if (item.type === "retire") store.retireKey(item.pubkey);
              else store.revokeKey(item.pubkey, NOW);
            }
            return observe(store, filterSets);
          });
          await withVault((storage) => {
            const target = openStore(storage, OWNER);
            expect(target.restore(source.backup)).toMatchObject({ ok: true });
            expect(observe(target, filterSets)).toEqual(source);
          });
        },
      ),
      { numRuns: 100 },
    );
  });
});
