import { runInDurableObject, SELF } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";
import {
  adminRequest,
  authEvent,
  connect,
  publicKeyOf,
  testSecretKey,
  vault,
  withStore,
  type TestClient,
} from "./test-support.ts";

const KEY_OWNER = testSecretKey("owner");
const OWNER = publicKeyOf(KEY_OWNER);
// Keys of this file only: the websocket test files share the DO's storage (vitest.config.ts).
const KEY_IMPORTER = testSecretKey("admin ws importer");
const IMPORTER = publicKeyOf(KEY_IMPORTER);
const ADDED = publicKeyOf(testSecretKey("admin ws added"));
const LIST = { op: "list" };

let clients: TestClient[] = [];

async function open(): Promise<{ client: TestClient; challenge: string }> {
  const opened = await connect(SELF);
  clients.push(opened.client);
  return opened;
}

/** An owner connection with a subscription, and an anonymous one. */
async function connections(): Promise<TestClient[]> {
  const owner = await open();
  owner.client.send(["AUTH", authEvent(KEY_OWNER, owner.challenge)]);
  expect((await owner.client.next())[2]).toBe(true);
  owner.client.send(["REQ", "sub", { kinds: [1] }]);
  expect((await owner.client.drain()).at(-1)).toEqual(["EOSE", "sub"]);
  const anonymous = await open();
  return [owner.client, anonymous.client];
}

async function admin(command: unknown): Promise<Record<string, unknown>> {
  const response = await SELF.fetch(adminRequest(command));
  return response.json();
}

async function openConnections(): Promise<number> {
  return runInDurableObject(vault(), (_instance, state) => state.getWebSockets().length);
}

afterEach(async () => {
  for (const client of clients) client.close();
  clients = [];
  await vault().closeAllConnections();
});

describe("OPS-2: an allowlist change through the admin route closes every connection", () => {
  it.each([
    ["adding a key", [], { op: "add", pubkey: ADDED, kinds: [1] }],
    ["retiring a key", [{ op: "add", pubkey: IMPORTER, kinds: [1] }], { op: "retire", pubkey: IMPORTER }],
    ["revoking a key", [], { op: "revoke", pubkey: IMPORTER }],
  ])("closes the owner's and an anonymous connection after %s", async (_name, setup, command) => {
    for (const step of setup) await admin(step);
    const [owner, anonymous] = await connections();
    expect(await admin(command)).toEqual({ ok: true, op: command.op, connectionsClosed: 2 });
    expect(await owner?.closed).toEqual({ code: 1012, reason: "the allowlist changed" });
    expect(await anonymous?.closed).toEqual({ code: 1012, reason: "the allowlist changed" });
    expect(await openConnections()).toBe(0);
  });

  it("keeps the connections when nothing changed", async () => {
    await withStore(OWNER, (store) => store.addKey(ADDED, { role: "importer", kinds: [1] }, 0));
    const [owner] = await connections();
    expect(await admin({ op: "add", pubkey: ADDED, kinds: [1] })).toMatchObject({
      ok: false,
      reason: "already-listed",
    });
    expect(await admin({ op: "revoke", pubkey: OWNER })).toMatchObject({ ok: false, reason: "owner-key" });
    expect(await admin(LIST)).toMatchObject({ ok: true });
    expect(await openConnections()).toBe(2);
    // The owner's subscription still answers.
    owner?.send(["REQ", "again", { kinds: [1], limit: 0 }]);
    expect(await owner?.next()).toEqual(["EOSE", "again"]);
  });
});
