import { runInDurableObject, SELF } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { readState, writeState, type ConnectionState } from "./connection.ts";
import type { EventStore } from "./store.ts";
import {
  authEvent,
  connect,
  evict,
  filterOf,
  publicKeyOf,
  signVerified,
  testSecretKey,
  vault,
  withStore as withStoreOf,
  type TestClient,
} from "./test-support.ts";

const KEY_OWNER = testSecretKey("owner");
const OWNER = publicKeyOf(KEY_OWNER);
const KEY_IMPORTER = testSecretKey("events importer");
const IMPORTER = publicKeyOf(KEY_IMPORTER);
const KEY_RETIRED = testSecretKey("events retired");
const KEY_STRANGER = testSecretKey("events stranger");

function withStore<T>(callback: (store: EventStore) => T): Promise<T> {
  return withStoreOf(OWNER, callback);
}

/** Whether the store holds the event, replaced versions included: read from the storage, not from any answer. */
function isStored(id: string): Promise<boolean> {
  return withStore((store) => store.query([filterOf({ ids: [id] })], 0).length > 0);
}

/** A unique `t` tag per test, so that a subscription sees only the events its test publishes. */
let topic = 0;
function nextTopic(): string {
  topic++;
  return `events-${topic}-${Date.now()}`;
}

/** A signed event; `created_at` defaults to now, as EV-4 limits the future and live tests need a current event. */
function sign(template: Parameters<typeof signVerified>[0], secretKey = KEY_OWNER) {
  return signVerified({ created_at: Math.floor(Date.now() / 1000), ...template }, secretKey);
}

let clients: TestClient[] = [];

async function open(): Promise<{ client: TestClient; challenge: string }> {
  const opened = await connect(SELF);
  clients.push(opened.client);
  return opened;
}

async function openAs(secretKey: Uint8Array): Promise<TestClient> {
  const { client, challenge } = await open();
  const auth = authEvent(secretKey, challenge);
  client.send(["AUTH", auth]);
  expect((await client.next())[1]).toBe(auth.id);
  return client;
}

/** An owner connection subscribed to `filter` as `sub`, with its stored events already drained. */
async function subscribe(filter: object, sub = "live"): Promise<TestClient> {
  const client = await openAs(KEY_OWNER);
  client.send(["REQ", sub, filter]);
  expect((await client.drain()).at(-1)).toEqual(["EOSE", sub]);
  return client;
}

/** Publishes `event` on `client` and returns the OK message. */
async function publish(client: TestClient, event: unknown): Promise<readonly unknown[]> {
  client.send(["EVENT", event]);
  return client.next();
}

/** Rewrites the attachment of every open connection with `change`. */
function changeStates(change: (state: ConnectionState) => ConnectionState): Promise<void> {
  return runInDurableObject(vault(), (_instance, state) => {
    for (const ws of state.getWebSockets()) {
      const current = readState(ws);
      if (current !== undefined) writeState(ws, change(current));
    }
  });
}

beforeEach(async () => {
  await withStore((store) => {
    store.addKey(IMPORTER, { role: "importer", kinds: [1, 5] }, 0);
    store.addKey(publicKeyOf(KEY_RETIRED), { role: "importer", kinds: [1] }, 0);
    store.retireKey(publicKeyOf(KEY_RETIRED));
  });
});

afterEach(async () => {
  vi.useRealTimers();
  for (const client of clients) client.close();
  clients = [];
  await vault().closeAllConnections();
});

describe("EVENT", () => {
  it("WR-1: stores the owner's event and answers OK true, without AUTH", async () => {
    const { client } = await open();
    const event = sign({ content: "owner note" });
    expect(await publish(client, event)).toEqual(["OK", event.id, true, ""]);
    expect(await isStored(event.id)).toBe(true);
  });

  it("answers a resubmission with duplicate:", async () => {
    const { client } = await open();
    const event = sign({ content: "twice" });
    await publish(client, event);
    expect(await publish(client, event)).toEqual(["OK", event.id, true, "duplicate: already have this event"]);
  });

  it.each([
    ["a key not on the allowlist", KEY_STRANGER, 1, "blocked: this key may not write here"],
    ["a retired key", KEY_RETIRED, 1, "blocked: this key is retired"],
    ["an importer outside its kinds", KEY_IMPORTER, 0, "restricted: this key may not write this kind"],
    ["the owner, kind 62 (WR-3)", KEY_OWNER, 62, "blocked: requests to vanish are not accepted"],
  ])("WR-1: refuses an event from %s and stores nothing", async (_name, secretKey, kind, message) => {
    const { client } = await open();
    const event = sign({ kind, content: "refused" }, secretKey);
    expect(await publish(client, event)).toEqual(["OK", event.id, false, message]);
    expect(await isStored(event.id)).toBe(false);
  });

  it("WR-1: stores an importer's event within its kinds", async () => {
    const { client } = await open();
    const event = sign({ kind: 1, content: "imported" }, KEY_IMPORTER);
    expect(await publish(client, event)).toEqual(["OK", event.id, true, ""]);
    expect(await isStored(event.id)).toBe(true);
  });

  it("EV-6: refuses an event already expired on receipt", async () => {
    const { client } = await open();
    const now = Math.floor(Date.now() / 1000);
    const event = sign({ tags: [["expiration", String(now - 1)]] });
    expect(await publish(client, event)).toEqual(["OK", event.id, false, "invalid: event has expired"]);
    expect(await isStored(event.id)).toBe(false);
  });

  it("refuses an event its author deleted", async () => {
    const { client } = await open();
    const target = sign({ content: "to delete" });
    const deletion = sign({ kind: 5, tags: [["e", target.id]] });
    await publish(client, deletion);
    expect(await publish(client, target)).toEqual([
      "OK",
      target.id,
      false,
      "blocked: this event was deleted by its author",
    ]);
  });

  it("EV-1: refuses an event whose signature does not verify, and an id that does not match", async () => {
    const { client } = await open();
    const event = sign({ content: "forged" });
    const forged = { ...event, sig: sign({ content: "other" }).sig };
    expect(await publish(client, forged)).toEqual(["OK", event.id, false, "invalid: signature verification failed"]);
    const tampered = { ...event, content: "tampered" };
    expect(await publish(client, tampered)).toEqual([
      "OK",
      event.id,
      false,
      "invalid: id does not match the event data",
    ]);
    expect(await isStored(event.id)).toBe(false);
  });

  it("EV-1, RES-1: measures the received event text against the 256 KiB limit", async () => {
    const { client } = await open();
    const event = sign({ content: "a".repeat(300 * 1024) });
    // Without parsing the oversized event there is no id for an OK, so the answer is a NOTICE.
    expect(await publish(client, event)).toEqual(["NOTICE", "invalid: event exceeds 262144 bytes"]);
    expect(await isStored(event.id)).toBe(false);
  });

  it("EV-1: verifies the received text, so a field given twice is checked with the value that is stored", async () => {
    const { client } = await open();
    const event = sign({ content: "first" });
    // JSON.parse keeps the last `content`; the event is verified and stored with that value, which the signature
    // does not cover.
    const text = JSON.stringify(event).replace('"content":"first"', '"content":"first","content":"second"');
    client.ws.send(`["EVENT",${text}]`);
    expect(await client.next()).toEqual(["OK", event.id, false, "invalid: id does not match the event data"]);
    expect(await isStored(event.id)).toBe(false);
  });

  describe("WR-2: protected events", () => {
    it("refuses a protected event on a connection without AUTH", async () => {
      const { client } = await open();
      const event = sign({ tags: [["-"]] });
      expect(await publish(client, event)).toEqual([
        "OK",
        event.id,
        false,
        "auth-required: this event may only be published by its author",
      ]);
      expect(await isStored(event.id)).toBe(false);
    });

    it.each([
      ["an importer", KEY_IMPORTER],
      ["a key not on the allowlist", KEY_STRANGER],
    ])("refuses the owner's protected event on a connection authenticated as %s", async (_name, secretKey) => {
      const client = await openAs(secretKey);
      const event = sign({ tags: [["-"]] });
      expect(await publish(client, event)).toEqual([
        "OK",
        event.id,
        false,
        "restricted: this event may only be published by its author",
      ]);
      expect(await isStored(event.id)).toBe(false);
    });

    it("accepts a protected event from its authenticated author, the owner or an importer", async () => {
      const owner = await openAs(KEY_OWNER);
      const ownEvent = sign({ tags: [["-"]] });
      expect(await publish(owner, ownEvent)).toEqual(["OK", ownEvent.id, true, ""]);
      const importer = await openAs(KEY_IMPORTER);
      const imported = sign({ kind: 1, tags: [["-"]] }, KEY_IMPORTER);
      expect(await publish(importer, imported)).toEqual(["OK", imported.id, true, ""]);
      expect([await isStored(ownEvent.id), await isStored(imported.id)]).toEqual([true, true]);
    });

    it("treats a `-` tag with more items as protected too", async () => {
      const { client } = await open();
      const event = sign({ tags: [["-", "x"]] });
      expect((await publish(client, event))[2]).toBe(false);
    });
  });

  describe("WR-5: ephemeral events", () => {
    it("delivers an ephemeral event without storing it", async () => {
      const t = nextTopic();
      const subscriber = await subscribe({ "#t": [t] });
      const { client } = await open();
      const event = sign({ kind: 20001, tags: [["t", t]] });
      expect(await publish(client, event)).toEqual(["OK", event.id, true, ""]);
      expect(await subscriber.drain()).toEqual([["EVENT", "live", event]]);
      expect(await isStored(event.id)).toBe(false);
    });

    it("neither stores nor delivers kind 22242 sent as EVENT", async () => {
      const t = nextTopic();
      const subscriber = await subscribe({ kinds: [22242] });
      const control = await subscribe({ "#t": [t] }, "control");
      const { client, challenge } = await open();
      const event = authEvent(KEY_OWNER, challenge, {
        tags: [
          ["t", t],
          ["challenge", challenge],
        ],
      });
      expect(await publish(client, event)).toEqual(["OK", event.id, true, ""]);
      expect(await subscriber.drain()).toEqual([]);
      expect(await control.drain()).toEqual([]);
      expect(await isStored(event.id)).toBe(false);
    });
  });
});

describe("RD-4: live delivery", () => {
  it("delivers a stored event to the owner's matching subscription, in canonical form", async () => {
    const t = nextTopic();
    const subscriber = await subscribe({ "#t": [t] });
    const other = await subscribe({ "#t": [`${t}-other`] }, "other");
    const { client } = await open();
    const event = sign({ tags: [["t", t]], content: "live" });
    // An unknown field is dropped (ST-7).
    client.send(["EVENT", { ...event, extra: "dropped" }]);
    expect(await client.next()).toEqual(["OK", event.id, true, ""]);
    expect(await subscriber.drain()).toEqual([["EVENT", "live", event]]);
    expect(await other.drain()).toEqual([]);
  });

  it("delivers nothing for a duplicate, a refusal or a version stored as history", async () => {
    const t = nextTopic();
    const subscriber = await subscribe({ "#t": [t] });
    const { client } = await open();
    const now = Math.floor(Date.now() / 1000);
    const current = sign({ kind: 10_002, created_at: now, tags: [["t", t]] });
    const older = sign({ kind: 10_002, created_at: now - 10, tags: [["t", t]] });
    await publish(client, current);
    expect(await subscriber.drain()).toEqual([["EVENT", "live", current]]);
    await publish(client, current);
    expect(await publish(client, older)).toEqual(["OK", older.id, true, ""]);
    await publish(client, sign({ tags: [["t", t]] }, KEY_STRANGER));
    expect(await subscriber.drain()).toEqual([]);
  });

  it("delivers to a replaced subscription by its new filters only, and nothing after CLOSE", async () => {
    const t = nextTopic();
    const subscriber = await subscribe({ "#t": [`${t}-old`] });
    subscriber.send(["REQ", "live", { "#t": [t] }]);
    expect(await subscriber.drain()).toEqual([["EOSE", "live"]]);
    const { client } = await open();
    const old = sign({ tags: [["t", `${t}-old`]] });
    const fresh = sign({ tags: [["t", t]] });
    await publish(client, old);
    await publish(client, fresh);
    expect(await subscriber.drain()).toEqual([["EVENT", "live", fresh]]);
    subscriber.send(["CLOSE", "live"]);
    await publish(client, sign({ tags: [["t", t]], content: "after close" }));
    expect(await subscriber.drain()).toEqual([]);
  });

  it("delivers nothing to a REQ refused before AUTH, after the connection authenticates", async () => {
    const t = nextTopic();
    const control = await subscribe({ "#t": [t] }, "control");
    const { client, challenge } = await open();
    client.send(["REQ", "early", { "#t": [t] }]);
    expect((await client.next())[0]).toBe("CLOSED");
    const auth = authEvent(KEY_OWNER, challenge);
    client.send(["AUTH", auth]);
    expect(await client.next()).toEqual(["OK", auth.id, true, ""]);
    const event = sign({ tags: [["t", t]] });
    expect(await publish(client, event)).toEqual(["OK", event.id, true, ""]);
    expect(await client.drain()).toEqual([]);
    expect(await control.drain()).toEqual([["EVENT", "control", event]]);
  });

  it("checks the connection at sending time: no delivery without the owner or past the deadline", async () => {
    const t = nextTopic();
    const withoutOwner = await subscribe({ "#t": [t] }, "a");
    const pastDeadline = await subscribe({ "#t": [t] }, "b");
    const importerOnly = await subscribe({ "#t": [t] }, "c");
    const control = await subscribe({ "#t": [t] }, "control");
    // Rewrite each subscriber's attachment as if its authority had changed after the REQ was accepted.
    await changeStates((state) => {
      const id = state.subscriptions[0]?.id;
      if (id === "a") return { ...state, pubkeys: [] };
      if (id === "b") return { ...state, deadline: 1 };
      if (id === "c") return { ...state, pubkeys: [IMPORTER] };
      return state;
    });
    const { client } = await open();
    const event = sign({ tags: [["t", t]] });
    await publish(client, event);
    expect(await control.drain()).toEqual([["EVENT", "control", event]]);
    expect(await withoutOwner.drain()).toEqual([]);
    expect(await importerOnly.drain()).toEqual([]);
    // A connection past its deadline is closed on its next message instead of being answered (RES-4).
    pastDeadline.send(["CLOSE", "b"]);
    expect(await pastDeadline.closed).toMatchObject({ code: 1008 });
    // Nothing came before the close: messages arrive in order, so a delivered event would already be queued.
    await expect(pastDeadline.nextText(100)).rejects.toThrow("no message from the relay");
  });

  it("ST-3, EV-6: never delivers an expired event; an expired ephemeral one is accepted, not stored", async () => {
    const t = nextTopic();
    const subscriber = await subscribe({ "#t": [t] });
    const { client } = await open();
    const now = Math.floor(Date.now() / 1000);
    const expired = sign({
      kind: 20001,
      tags: [
        ["t", t],
        ["expiration", String(now)],
      ],
    });
    // NIP-40: "An expiration timestamp does not affect storage of ephemeral events."
    expect(await publish(client, expired)).toEqual(["OK", expired.id, true, ""]);
    const live = sign({
      kind: 20001,
      tags: [
        ["t", t],
        ["expiration", String(now + 60)],
      ],
    });
    await publish(client, live);
    expect(await subscriber.drain()).toEqual([["EVENT", "live", live]]);
    expect(await isStored(expired.id)).toBe(false);
  });

  it("RD-3: keeps delivering to a subscription after the DO is evicted", async () => {
    const t = nextTopic();
    const subscriber = await subscribe({ "#t": [t] });
    const { client } = await open();
    const evicted = await evict();
    const event = sign({ tags: [["t", t]] });
    expect(await publish(client, event)).toEqual(["OK", event.id, true, ""]);
    expect(await subscriber.drain()).toEqual([["EVENT", "live", event]]);
    await evicted();
  });
});
