import { canonicalEventJson, type NostrEvent, type VerifiedEvent } from "@zenith/core";
import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { parseVaultConfig, toRejectionResponse, WRITE_REJECTIONS, type WriteRejection } from "./allowlist.ts";
import { EventStore } from "./store.ts";
import { filterOf, openStore, publicKeyOf, signVerified, testConfig, testSecretKey } from "./test-support.ts";

const KEY_OWNER = testSecretKey("owner");
const KEY_BLOG = testSecretKey("blog importer");
const KEY_MASTODON = testSecretKey("mastodon importer");
const KEY_STRANGER = testSecretKey("stranger");
const OWNER = publicKeyOf(KEY_OWNER);
const BLOG = publicKeyOf(KEY_BLOG);
const MASTODON = publicKeyOf(KEY_MASTODON);
const STRANGER = publicKeyOf(KEY_STRANGER);
const NOW = 1_000;

function ev(template: Partial<NostrEvent>, key: Uint8Array): VerifiedEvent {
  return signVerified({ created_at: 100, ...template }, key);
}

/** A new Vault DO's storage, with the owner and the two importers of WR-1's examples. */
async function withVault<T>(callback: (store: EventStore, storage: DurableObjectStorage) => T): Promise<T> {
  const stub = env.VAULT.get(env.VAULT.newUniqueId());
  return runInDurableObject(stub, (_instance, state) =>
    callback(
      openStore(state.storage, OWNER, [
        [BLOG, [30023, 5]],
        [MASTODON, [1, 5]],
      ]),
      state.storage,
    ),
  );
}

function rejectionOf(store: EventStore, event: VerifiedEvent): WriteRejection | undefined {
  const result = store.apply(event, NOW);
  return result.ok ? undefined : result.code;
}

describe("configuration", () => {
  it.each([
    [{}, "missing-owner"],
    [{ OWNER_PUBKEY: "" }, "missing-owner"],
    [{ OWNER_PUBKEY: OWNER.toUpperCase() }, "bad-owner"],
    [{ OWNER_PUBKEY: OWNER.slice(1) }, "bad-owner"],
    [{ OWNER_PUBKEY: `npub1${OWNER.slice(5)}` }, "bad-owner"],
    [{ OWNER_PUBKEY: 1 }, "bad-owner"],
  ])("refuses %j", (vars, code) => {
    expect(parseVaultConfig(vars)).toEqual({ ok: false, code });
  });

  it("accepts a lowercase hex key", () => {
    expect(parseVaultConfig({ OWNER_PUBKEY: OWNER })).toEqual({ ok: true, config: { owner: OWNER } });
  });

  it("takes only a parsed configuration", async () => {
    await withVault((_store, storage) => {
      // @ts-expect-error a plain object is not a VaultConfig
      expect(EventStore.open(storage, { owner: OWNER }, NOW)).toMatchObject({ ok: true });
    });
  });
});

describe("write authorization (WR-1, WR-3)", () => {
  it.each([0, 1, 3, 5, 7, 45, 1984, 10002, 30023, 39999, 40000, 65535])(
    "WR-1: the owner writes kind %i",
    async (kind) => {
      await withVault((store) => {
        expect(store.apply(ev({ kind }, KEY_OWNER), NOW)).toEqual({ ok: true, outcome: "stored" });
      });
    },
  );

  it("WR-1: the owner's ephemeral events pass authorization and are not stored (WR-5)", async () => {
    await withVault((store) => {
      expect(store.apply(ev({ kind: 22242 }, KEY_OWNER), NOW)).toEqual({ ok: true, outcome: "not-stored-ephemeral" });
    });
  });

  // NIP-62: "Kind `62` requests a specific relay to delete everything, including NIP-09 Deletion Events, from the
  // `.pubkey` until its `.created_at`."
  it.each([
    ["the owner", KEY_OWNER],
    ["an importer", KEY_MASTODON],
    ["a key not listed", KEY_STRANGER],
  ])("WR-3: refuses kind 62 from %s with blocked:", async (_name, key) => {
    await withVault((store) => {
      const vanish = ev({ kind: 62, tags: [["relay", "ALL_RELAYS"]] }, key);
      expect(rejectionOf(store, vanish)).toBe("vanish-request");
      expect(toRejectionResponse("vanish-request").message).toMatch(/^blocked: /);
      expect(store.canonicalEvents()).toEqual([]);
    });
  });

  it.each([
    [0, "kind-not-allowed"],
    [1, "kind-not-allowed"],
    [30024, "kind-not-allowed"],
    [30023, undefined],
    [5, undefined],
  ] as const)("WR-1: the blog importer writing kind %i gives %s", async (kind, rejection) => {
    await withVault((store) => {
      expect(rejectionOf(store, ev({ kind }, KEY_BLOG))).toBe(rejection);
    });
  });

  it.each([
    [0, "kind-not-allowed"],
    [30023, "kind-not-allowed"],
    [1, undefined],
    [5, undefined],
  ] as const)("WR-1: the Mastodon importer writing kind %i gives %s", async (kind, rejection) => {
    await withVault((store) => {
      expect(rejectionOf(store, ev({ kind }, KEY_MASTODON))).toBe(rejection);
    });
  });

  it("WR-1: refuses a key that is not listed", async () => {
    await withVault((store) => {
      expect(rejectionOf(store, ev({ kind: 1 }, KEY_STRANGER))).toBe("unknown-key");
    });
  });

  it("WR-1: refuses a retired key and a revoked key at once", async () => {
    await withVault((store) => {
      expect(rejectionOf(store, ev({ kind: 1, content: "before" }, KEY_MASTODON))).toBeUndefined();
      expect(store.retireKey(MASTODON)).toEqual({ ok: true });
      expect(rejectionOf(store, ev({ kind: 1, content: "retired" }, KEY_MASTODON))).toBe("retired-key");
      expect(store.revokeKey(MASTODON, NOW)).toEqual({ ok: true });
      expect(rejectionOf(store, ev({ kind: 1, content: "revoked" }, KEY_MASTODON))).toBe("unknown-key");
      expect(store.canonicalEvents()).toHaveLength(1);
    });
  });

  it("WR-1: a key added later writes only after it is added", async () => {
    await withVault((store) => {
      const note = ev({ kind: 1 }, KEY_STRANGER);
      expect(rejectionOf(store, note)).toBe("unknown-key");
      expect(store.addKey(STRANGER, { role: "importer", kinds: [1] }, NOW)).toEqual({ ok: true });
      expect(store.apply(note, NOW)).toEqual({ ok: true, outcome: "stored" });
    });
  });

  it("WR-1: only the configured key is the owner; reopening with another owner retires the previous one", async () => {
    await withVault((store, storage) => {
      expect(rejectionOf(store, ev({ kind: 0 }, KEY_STRANGER))).toBe("unknown-key");
      const opened = EventStore.open(storage, testConfig(STRANGER), NOW);
      if (!opened.ok) throw new Error(opened.code);
      const reopened = opened.store;
      expect(reopened.apply(ev({ kind: 0 }, KEY_STRANGER), NOW)).toEqual({ ok: true, outcome: "stored" });
      expect(rejectionOf(reopened, ev({ kind: 0 }, KEY_OWNER))).toBe("retired-key");
      expect(reopened.listKeys().keys.filter((key) => key.role === "owner")).toEqual([
        { pubkey: STRANGER, role: "owner", addedAt: NOW },
      ]);
      expect(reopened.listKeys().keys.find((key) => key.pubkey === OWNER)).toMatchObject({
        role: "retired",
        kinds: [],
      });
    });
  });

  // ST-8: making a revoked or retired key the owner would reverse the revocation or the retirement.
  it.each([
    ["revoked", "owner-revoked", (store: EventStore) => store.revokeKey(MASTODON, NOW)],
    ["retired", "owner-retired", (store: EventStore) => store.retireKey(MASTODON)],
  ] as const)(
    "ST-8: does not open with a %s key configured as the owner, and changes nothing",
    async (_name, code, act) => {
      await withVault((store, storage) => {
        expect(act(store)).toEqual({ ok: true });
        const before = store.listKeys();
        expect(EventStore.open(storage, testConfig(MASTODON), NOW)).toEqual({ ok: false, code });
        expect(store.listKeys()).toEqual(before);
        expect(rejectionOf(store, ev({ kind: 1 }, KEY_MASTODON))).not.toBeUndefined();
      });
    },
  );

  it("ST-8: does not open with the previous owner configured again, since it was retired", async () => {
    await withVault((_store, storage) => {
      expect(EventStore.open(storage, testConfig(STRANGER), NOW)).toMatchObject({ ok: true });
      expect(EventStore.open(storage, testConfig(OWNER), NOW)).toEqual({ ok: false, code: "owner-retired" });
    });
  });

  it.each<[WriteRejection, RegExp]>([
    ["vanish-request", /^blocked: /],
    ["unknown-key", /^blocked: /],
    ["retired-key", /^blocked: /],
    ["kind-not-allowed", /^restricted: /],
  ])("answers %s with %s", (rejection, prefix) => {
    expect(toRejectionResponse(rejection)).toEqual({ accepted: false, message: expect.stringMatching(prefix) });
  });

  it("has a response for every rejection", () => {
    for (const rejection of WRITE_REJECTIONS) expect(toRejectionResponse(rejection).message).toMatch(/^\w+: \S/);
  });
});

describe("allowlist operations", () => {
  it.each([
    ["an uppercase key", () => [STRANGER.toUpperCase(), [1]] as const, "bad-pubkey"],
    ["no kinds", () => [STRANGER, []] as const, "bad-kinds"],
    ["kind 62", () => [STRANGER, [1, 62]] as const, "bad-kinds"],
    ["a kind out of range", () => [STRANGER, [65536]] as const, "bad-kinds"],
    ["a fractional kind", () => [STRANGER, [1.5]] as const, "bad-kinds"],
    ["the owner", () => [OWNER, [1]] as const, "owner-key"],
    ["a listed importer", () => [BLOG, [1]] as const, "already-listed"],
  ])("refuses to add %s", async (_name, args, code) => {
    await withVault((store) => {
      const [pubkey, kinds] = args();
      const before = store.listKeys();
      expect(store.addKey(pubkey, { role: "importer", kinds }, NOW)).toEqual({ ok: false, code });
      expect(store.listKeys()).toEqual(before);
    });
  });

  it("refuses to add a retired key again, which would make it writable", async () => {
    await withVault((store) => {
      store.retireKey(BLOG);
      expect(store.addKey(BLOG, { role: "importer", kinds: [30023] }, NOW)).toEqual({
        ok: false,
        code: "already-listed",
      });
    });
  });

  it("DATA-4, ST-8: never lists a revoked key again", async () => {
    await withVault((store) => {
      expect(store.revokeKey(BLOG, NOW)).toEqual({ ok: true });
      expect(store.addKey(BLOG, { role: "importer", kinds: [30023] }, NOW)).toEqual({
        ok: false,
        code: "revoked-key",
      });
      expect(store.listKeys().revoked).toEqual([{ pubkey: BLOG, revokedAt: NOW }]);
    });
  });

  it("refuses to retire or revoke the owner, and reports operations that change nothing", async () => {
    await withVault((store) => {
      expect(store.retireKey(OWNER)).toEqual({ ok: false, code: "owner-key" });
      expect(store.revokeKey(OWNER, NOW)).toEqual({ ok: false, code: "owner-key" });
      expect(store.retireKey(STRANGER)).toEqual({ ok: false, code: "not-listed" });
      expect(store.revokeKey(STRANGER, NOW)).toEqual({ ok: false, code: "not-listed" });
      expect(store.retireKey(BLOG)).toEqual({ ok: true });
      expect(store.retireKey(BLOG)).toEqual({ ok: false, code: "unchanged" });
      expect(store.revokeKey(BLOG, NOW)).toEqual({ ok: true });
      expect(store.revokeKey(BLOG, NOW)).toEqual({ ok: false, code: "unchanged" });
      expect(store.retireKey(BLOG)).toEqual({ ok: false, code: "not-listed" });
    });
  });

  it("lists the keys with their roles and kinds", async () => {
    await withVault((store) => {
      store.addKey(STRANGER, { role: "importer", kinds: [5, 1, 5] }, NOW);
      store.retireKey(MASTODON);
      expect(store.listKeys()).toEqual({
        keys: [
          { pubkey: OWNER, role: "owner", addedAt: 0 },
          { pubkey: BLOG, role: "importer", kinds: [5, 30023], addedAt: 0 },
          { pubkey: MASTODON, role: "retired", kinds: [1, 5], addedAt: 0 },
          { pubkey: STRANGER, role: "importer", kinds: [1, 5], addedAt: NOW },
        ].toSorted((a, b) => (a.pubkey < b.pubkey ? -1 : 1)),
        revoked: [],
      });
    });
  });
});

describe("retired and revoked keys' events (ST-5, DATA-4)", () => {
  it("ST-5: keeps a retired key's events, returns them by ids only", async () => {
    await withVault((store) => {
      const note = ev({ kind: 1, content: "old" }, KEY_MASTODON);
      store.apply(note, NOW);
      store.retireKey(MASTODON);
      expect(store.canonicalEvents()).toHaveLength(1);
      expect(store.query([filterOf({})], NOW)).toEqual([]);
      expect(store.query([filterOf({ authors: [MASTODON] })], NOW)).toEqual([]);
      expect(store.query([filterOf({ ids: [note.id] })], NOW)).toHaveLength(1);
    });
  });

  it("DATA-4: treats a revoked key's events like a retired key's", async () => {
    await withVault((store) => {
      const note = ev({ kind: 1, content: "leaked?" }, KEY_MASTODON);
      store.apply(note, NOW);
      store.revokeKey(MASTODON, NOW);
      expect(store.canonicalEvents()).toHaveLength(1);
      expect(store.query([filterOf({ kinds: [1] })], NOW)).toEqual([]);
      expect(store.query([filterOf({ ids: [note.id] })], NOW)).toHaveLength(1);
    });
  });

  it("DATA-4, ST-5: rotates an importer key without rewriting history", async () => {
    await withVault((store) => {
      const KEY_NEW = testSecretKey("blog importer 2");
      const old = ev({ kind: 30023, created_at: 200, tags: [["d", "post"]], content: "old key" }, KEY_BLOG);
      store.apply(old, NOW);
      expect(store.addKey(publicKeyOf(KEY_NEW), { role: "importer", kinds: [30023, 5] }, NOW)).toEqual({
        ok: true,
      });
      // Imported again under the new key, with an older created_at: the address includes the pubkey, so neither
      // version replaces the other.
      const imported = ev({ kind: 30023, created_at: 100, tags: [["d", "post"]], content: "new key" }, KEY_NEW);
      expect(store.apply(imported, NOW)).toEqual({ ok: true, outcome: "stored" });
      expect(store.query([filterOf({ kinds: [30023] })], NOW)).toHaveLength(2);
      expect(store.retireKey(BLOG)).toEqual({ ok: true });
      expect(store.query([filterOf({ kinds: [30023] })], NOW)).toEqual([canonicalEventJson(imported)]);
      expect(store.query([filterOf({ ids: [old.id] })], NOW)).toEqual([canonicalEventJson(old)]);
    });
  });
});
