import { evictDurableObject, runDurableObjectAlarm, runInDurableObject, SELF } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { readState, type ConnectionState } from "./connection.ts";
import { EventStore } from "./store.ts";
import {
  authEvent,
  connect,
  publicKeyOf,
  signVerified,
  testConfig,
  testSecretKey,
  TEST_RELAY_URL,
  type TestClient,
} from "./test-support.ts";
import { AUTH_TIMEOUT_MS, PING, PONG, VAULT_NAME } from "./vault.ts";

const KEY_OWNER = testSecretKey("owner");
const OWNER = publicKeyOf(KEY_OWNER);
const KEY_IMPORTER = testSecretKey("protocol importer");
const KEY_RETIRED = testSecretKey("protocol retired");
const KEY_STRANGER = testSecretKey("protocol stranger");

const vault = () => env.VAULT.getByName(VAULT_NAME);

/** Runs `callback` on an EventStore opened on the Vault DO's storage, as the DO opens it. */
function withStore<T>(callback: (store: EventStore) => T): Promise<T> {
  return runInDurableObject(vault(), (_instance, state) => {
    const opened = EventStore.open(state.storage, testConfig(OWNER), 0);
    if (!opened.ok) throw new Error(opened.error);
    return callback(opened.store);
  });
}

/**
 * Evicts the Vault DO, keeping its hibernated WebSockets. The returned check, called once the connection has been
 * used again, confirms that another instance served it: an instance created by runInDurableObject cannot use the
 * storage for a WebSocket message, so the check runs last.
 */
async function evict(): Promise<() => Promise<void>> {
  const before = await runInDurableObject(vault(), (instance) => new WeakRef(instance));
  await evictDurableObject(vault());
  return async () => {
    const after = await runInDurableObject(vault(), (instance) => instance);
    expect(before.deref()).not.toBe(after);
  };
}

/** Drops the attachment of every connection, as if it had never been written. */
function dropAttachments(): Promise<void> {
  return runInDurableObject(vault(), (_instance, state) => {
    for (const ws of state.getWebSockets()) ws.serializeAttachment(null);
  });
}

/** Moves the clock past the RES-4 deadline of connections opened now, and runs the alarm. */
async function idlePastDeadline(): Promise<void> {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(Date.now() + AUTH_TIMEOUT_MS + 1000);
  expect(await runDurableObjectAlarm(vault())).toBe(true);
}

/** The attachment state of every open connection; a connection without an attachment gives undefined. */
function connectionStates(): Promise<(ConnectionState | undefined)[]> {
  return runInDurableObject(vault(), (_instance, state) => state.getWebSockets().map((ws) => readState(ws)));
}

/** The ids of every registered subscription, over every open connection. */
async function subscriptionIds(): Promise<string[]> {
  return (await connectionStates()).flatMap(
    (state) => state?.subscriptions.map((subscription) => subscription.id) ?? [],
  );
}

let clients: TestClient[] = [];

async function open(): Promise<{ client: TestClient; challenge: string }> {
  const opened = await connect(SELF);
  clients.push(opened.client);
  return opened;
}

/** Opens a connection and authenticates it with `secretKey`, returning the OK message. */
async function openAs(secretKey: Uint8Array): Promise<{ client: TestClient; ok: readonly unknown[] }> {
  const { client, challenge } = await open();
  client.send(["AUTH", authEvent(secretKey, challenge)]);
  return { client, ok: await client.next() };
}

beforeEach(async () => {
  // The DO's storage is shared by the websocket test files (vitest.config.ts), so the keys are added once.
  await withStore((store) => {
    store.addKey(publicKeyOf(KEY_IMPORTER), { role: "importer", kinds: [1] }, 0);
    store.addKey(publicKeyOf(KEY_RETIRED), { role: "importer", kinds: [1] }, 0);
    store.retireKey(publicKeyOf(KEY_RETIRED));
  });
});

afterEach(async () => {
  vi.useRealTimers();
  for (const client of clients) client.close();
  clients = [];
  // Close whatever a test left open on the relay side too, so that later tests start without connections.
  await vault().closeAllConnections();
});

describe("connection", () => {
  it("RD-2: sends a fresh random challenge on each connection", async () => {
    const first = await open();
    const second = await open();
    expect(first.challenge).toMatch(/^[0-9a-f]{64}$/);
    expect(second.challenge).not.toBe(first.challenge);
  });

  it("RES-3: answers the ping without the message handler", async () => {
    const { client } = await open();
    client.ws.send(PING);
    expect(await client.nextText()).toBe(PONG);
  });

  it("answers malformed JSON, an unknown type and a binary message with a NOTICE", async () => {
    const { client } = await open();
    client.ws.send("not json");
    expect(await client.next()).toEqual(["NOTICE", "invalid: message is not valid JSON"]);
    client.send(["COUNT", "x", {}]);
    expect(await client.next()).toEqual(["NOTICE", "invalid: unknown message type"]);
    client.send({ type: "REQ" });
    expect(await client.next()).toEqual(["NOTICE", "invalid: message must be a JSON array that starts with its type"]);
    client.ws.send(new Uint8Array([0x5b, 0x5d]));
    expect(await client.next()).toEqual(["NOTICE", "invalid: binary messages are not accepted"]);
  });

  it("RES-1: refuses a message over 512 KiB before parsing it", async () => {
    const { client } = await open();
    const padding = "a".repeat(512 * 1024);
    client.ws.send(`["REQ","x",{"#t":["${padding}"]}]`);
    expect(await client.next()).toEqual(["NOTICE", "invalid: message exceeds 524288 bytes"]);
  });
});

describe("AUTH", () => {
  it("RD-2: accepts the owner's AUTH for this connection's challenge and the configured relay", async () => {
    const { client, challenge } = await open();
    const event = authEvent(KEY_OWNER, challenge);
    client.send(["AUTH", event]);
    expect(await client.next()).toEqual(["OK", event.id, true, ""]);
  });

  it("RD-2: refuses another connection's challenge", async () => {
    const first = await open();
    const { client } = await open();
    const event = authEvent(KEY_OWNER, first.challenge);
    client.send(["AUTH", event]);
    expect(await client.next()).toEqual(["OK", event.id, false, "invalid: AUTH event challenge does not match"]);
  });

  it("RD-2: compares the relay tag with the configured URL, not the request's Host", async () => {
    const { client, challenge } = await connect(SELF, "https://other-host.example/");
    clients.push(client);
    const event = authEvent(KEY_OWNER, challenge, {}, "wss://other-host.example/");
    client.send(["AUTH", event]);
    expect(await client.next()).toEqual(["OK", event.id, false, "invalid: AUTH event relay does not match this relay"]);
    const configured = authEvent(KEY_OWNER, challenge, {}, TEST_RELAY_URL);
    client.send(["AUTH", configured]);
    expect(await client.next()).toEqual(["OK", configured.id, true, ""]);
  });

  it("RD-2: refuses an AUTH event created 11 minutes ago, and one of another kind", async () => {
    const { client, challenge } = await open();
    const stale = authEvent(KEY_OWNER, challenge, { created_at: Math.floor(Date.now() / 1000) - 660 });
    client.send(["AUTH", stale]);
    expect(await client.next()).toEqual([
      "OK",
      stale.id,
      false,
      "invalid: AUTH event created_at is too far from the current time",
    ]);
    const kind1 = authEvent(KEY_OWNER, challenge, { kind: 1 });
    client.send(["AUTH", kind1]);
    expect(await client.next()).toEqual(["OK", kind1.id, false, "invalid: AUTH event must be kind 22242"]);
  });

  it("EV-1: refuses an AUTH event whose signature does not verify", async () => {
    const { client, challenge } = await open();
    const event = authEvent(KEY_OWNER, challenge);
    client.send(["AUTH", { ...event, sig: authEvent(KEY_STRANGER, challenge).sig }]);
    expect(await client.next()).toEqual(["OK", event.id, false, "invalid: signature verification failed"]);
  });

  it("EV-1, RES-1: measures the AUTH event's received text against the 256 KiB event limit", async () => {
    const { client, challenge } = await open();
    const event = authEvent(KEY_OWNER, challenge, { content: "a".repeat(300 * 1024) });
    client.send(["AUTH", event]);
    expect(await client.next()).toEqual(["NOTICE", "invalid: event exceeds 262144 bytes"]);
  });

  it("answers a key that is not on the allowlist with restricted:", async () => {
    const { client, ok } = await openAs(KEY_STRANGER);
    expect(ok).toEqual(["OK", expect.any(String), false, "restricted: this key is not allowed here"]);
    expect(await client.drain()).toEqual([]);
  });
});

describe("REQ", () => {
  it("RD-1: answers an unauthenticated REQ with auth-required: and does not register it", async () => {
    const event = signVerified({ kind: 1, created_at: 100, content: "rd-1 unauthenticated" }, KEY_OWNER);
    await withStore((store) => store.apply(event, 200));
    const { client, challenge } = await open();
    client.send(["REQ", "sub", { ids: [event.id] }]);
    expect(await client.next()).toEqual(["CLOSED", "sub", "auth-required: authenticate as the owner to read"]);
    expect(await subscriptionIds()).toEqual([]);
    // RD-4 (registration): authenticating afterwards does not start the refused subscription.
    const auth = authEvent(KEY_OWNER, challenge);
    client.send(["AUTH", auth]);
    expect(await client.drain()).toEqual([["OK", auth.id, true, ""]]);
    expect(await subscriptionIds()).toEqual([]);
    // The check sees registered subscriptions: one accepted now is there, the refused one still is not.
    client.send(["REQ", "control", { limit: 0 }]);
    expect(await client.drain()).toEqual([["EOSE", "control"]]);
    expect(await subscriptionIds()).toEqual(["control"]);
  });

  it.each([
    ["a key not on the allowlist", KEY_STRANGER],
    ["an importer key", KEY_IMPORTER],
    ["a retired key", KEY_RETIRED],
  ])("RD-1: answers a REQ authenticated as %s with restricted:", async (_name, secretKey) => {
    const { client } = await openAs(secretKey);
    client.send(["REQ", "sub", { kinds: [1] }]);
    expect(await client.next()).toEqual(["CLOSED", "sub", "restricted: only the owner may read"]);
    expect(await client.drain()).toEqual([]);
    expect(await subscriptionIds()).toEqual([]);
  });

  it("returns the owner's stored events newest first, then EOSE", async () => {
    const older = signVerified({ kind: 1, created_at: 100, content: "req older" }, KEY_OWNER);
    const newer = signVerified({ kind: 1, created_at: 101, content: "req newer" }, KEY_OWNER);
    await withStore((store) => [store.apply(older, 200), store.apply(newer, 200)]);
    const { client } = await openAs(KEY_OWNER);
    client.send(["REQ", "sub", { ids: [older.id, newer.id] }]);
    expect(await client.drain()).toEqual([
      ["EVENT", "sub", newer],
      ["EVENT", "sub", older],
      ["EOSE", "sub"],
    ]);
  });

  it("answers an invalid filter with CLOSED and the filter's prefix", async () => {
    const { client } = await openAs(KEY_OWNER);
    client.send(["REQ", "sub", { search: "x" }]);
    expect(await client.next()).toEqual(["CLOSED", "sub", "unsupported: filter contains an unsupported key: search"]);
    client.send(["REQ", "sub"]);
    expect(await client.next()).toEqual(["CLOSED", "sub", "invalid: REQ has no filters"]);
    client.send(["REQ", "sub", ...Array.from({ length: 11 }, () => ({}))]);
    expect(await client.next()).toEqual(["CLOSED", "sub", "invalid: more than 10 filters"]);
  });

  it("RES-1: refuses the 21st subscription and accepts a replacement of an open one", async () => {
    const { client } = await openAs(KEY_OWNER);
    for (let i = 0; i < 20; i++) client.send(["REQ", `sub${i}`, { limit: 0 }]);
    client.send(["REQ", "sub0", { limit: 0 }]);
    client.send(["REQ", "sub20", { limit: 0 }]);
    const received = await client.drain();
    expect(received.filter((message) => message[0] === "EOSE")).toHaveLength(21);
    expect(received.at(-1)).toEqual(["CLOSED", "sub20", "invalid: more than 20 subscriptions"]);
    // After a CLOSE there is room again.
    client.send(["CLOSE", "sub1"]);
    client.send(["REQ", "sub20", { limit: 0 }]);
    expect(await client.drain()).toEqual([["EOSE", "sub20"]]);
  });

  it("RES-1: refuses a REQ whose subscription would not fit in the 15 KiB attachment", async () => {
    const { client } = await openAs(KEY_OWNER);
    const values = Array.from({ length: 900 }, (_, i) => `value-${String(i).padStart(10, "0")}`);
    client.send(["REQ", "big", { "#t": values }]);
    expect(await client.next()).toEqual([
      "CLOSED",
      "big",
      "invalid: the subscription does not fit in the connection state",
    ]);
    // The refused subscription takes no room: a small one still fits.
    client.send(["REQ", "small", { limit: 0 }]);
    expect(await client.drain()).toEqual([["EOSE", "small"]]);
  });
});

describe("RD-3: hibernation", () => {
  it("keeps the owner's authentication after the DO is evicted", async () => {
    const event = signVerified({ kind: 1, created_at: 100, content: "rd-3 hibernation" }, KEY_OWNER);
    await withStore((store) => store.apply(event, 200));
    const { client } = await openAs(KEY_OWNER);
    const evicted = await evict();
    client.send(["REQ", "sub", { ids: [event.id] }]);
    expect(await client.drain()).toEqual([
      ["EVENT", "sub", event],
      ["EOSE", "sub"],
    ]);
    await evicted();
  });

  it("keeps an unauthenticated connection unauthenticated after the DO is evicted", async () => {
    const { client } = await open();
    const evicted = await evict();
    client.send(["REQ", "sub", { kinds: [1] }]);
    expect(await client.next()).toEqual(["CLOSED", "sub", "auth-required: authenticate as the owner to read"]);
    await evicted();
  });

  it("keeps the challenge after the DO is evicted", async () => {
    const { client, challenge } = await open();
    const evicted = await evict();
    const event = authEvent(KEY_OWNER, challenge);
    client.send(["AUTH", event]);
    expect(await client.next()).toEqual(["OK", event.id, true, ""]);
    await evicted();
  });

  it("treats a connection without an attachment as unauthenticated, even after the owner's AUTH", async () => {
    const { client } = await openAs(KEY_OWNER);
    await dropAttachments();
    // Unauthenticated and past its RES-4 deadline: closed without an answer.
    client.send(["REQ", "sub", { kinds: [1] }]);
    expect(await client.closed).toEqual({ code: 1008, reason: "auth-required: authentication timed out" });
    expect(await subscriptionIds()).toEqual([]);
  });
});

describe("RES-4: unauthenticated connections are closed after 30 seconds", () => {
  it("closes an idle unauthenticated connection", async () => {
    const { client } = await open();
    await idlePastDeadline();
    expect(await client.closed).toEqual({ code: 1008, reason: "auth-required: authentication timed out" });
  });

  it("keeps a connection open until its deadline", async () => {
    const { client } = await open();
    expect(await runDurableObjectAlarm(vault())).toBe(true);
    expect(await client.drain()).toEqual([]);
  });

  it.each([
    ["a key not on the allowlist", KEY_STRANGER],
    ["a retired key", KEY_RETIRED],
  ])("closes a connection authenticated as %s", async (_name, secretKey) => {
    const { client } = await openAs(secretKey);
    await idlePastDeadline();
    expect(await client.closed).toEqual({ code: 1008, reason: "auth-required: authentication timed out" });
  });

  it.each([
    ["the owner", KEY_OWNER],
    ["an importer", KEY_IMPORTER],
  ])("keeps a connection authenticated as %s open", async (_name, secretKey) => {
    const { client } = await openAs(secretKey);
    const idle = await open();
    await idlePastDeadline();
    expect(await idle.client.closed).toMatchObject({ code: 1008 });
    expect(await client.drain()).toEqual([]);
  });

  it("verifies, stores and logs nothing for an AUTH past the deadline, even if the alarm has not run", async () => {
    const { client, challenge } = await open();
    const logs: unknown[][] = [];
    for (const method of ["log", "info", "warn", "error", "debug"] as const) {
      vi.spyOn(console, method).mockImplementation((...args: unknown[]) => logs.push(args));
    }
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + AUTH_TIMEOUT_MS + 1000);
    // A valid owner AUTH for this connection, created at the moved time, so that only the deadline refuses it.
    client.send(["AUTH", authEvent(KEY_OWNER, challenge)]);
    expect(await client.closed).toEqual({ code: 1008, reason: "auth-required: authentication timed out" });
    // No OK came before the close: messages arrive in order, so one would already be queued.
    await expect(client.nextText(100)).rejects.toThrow("no message from the relay");
    expect(logs).toEqual([]);
  });

  it("answers nothing on a connection that is no longer open, a client that ignores the close included", async () => {
    const { challenge } = await open();
    const outcome = await runInDurableObject(vault(), async (instance, state) => {
      const [ws] = state.getWebSockets();
      if (ws === undefined) throw new Error("no connection");
      ws.close(1000, "closing");
      const send = vi.spyOn(ws, "send");
      await instance.webSocketMessage(ws, JSON.stringify(["AUTH", authEvent(KEY_OWNER, challenge)]));
      await instance.webSocketMessage(ws, "not json");
      return { sends: send.mock.calls.length, state: readState(ws) };
    });
    expect(outcome).toEqual({ sends: 0, state: expect.objectContaining({ authenticated: false, pubkeys: [] }) });
  });

  it("closes a connection whose attachment was lost", async () => {
    const { client } = await openAs(KEY_OWNER);
    await dropAttachments();
    await idlePastDeadline();
    expect(await client.closed).toMatchObject({ code: 1008 });
  });

  it("closes an idle connection after the DO is evicted", async () => {
    const { client } = await open();
    await evictDurableObject(vault());
    await idlePastDeadline();
    expect(await client.closed).toMatchObject({ code: 1008 });
  });
});

describe("OPS-2", () => {
  it("closes every connection, authenticated or not", async () => {
    const owner = await openAs(KEY_OWNER);
    const anonymous = await open();
    expect(await vault().closeAllConnections()).toBe(2);
    expect(await owner.client.closed).toEqual({ code: 1012, reason: "the allowlist changed" });
    expect(await anonymous.client.closed).toEqual({ code: 1012, reason: "the allowlist changed" });
  });
});
