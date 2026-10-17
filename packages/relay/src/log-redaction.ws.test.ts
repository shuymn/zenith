import { runInDurableObject, SELF } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import { EventStore } from "./store.ts";
import {
  authEvent,
  connect,
  publicKeyOf,
  signVerified,
  testConfig,
  testSecretKey,
  type TestClient,
} from "./test-support.ts";
import { VAULT_NAME } from "./vault.ts";

// DATA-1: logs carry no event content and no AUTH events. Every path below carries dummy secrets in event content,
// filters, AUTH events and an injected error message; none of them may reach the console.
const CONTENT = "zenith-dummy-event-content";
const FILTER = "zenith-dummy-filter-value";
const ERROR = "zenith-dummy-error-message";
const KEY_OWNER = testSecretKey("owner");
const KEY_STRANGER = testSecretKey("log redaction stranger");

const vault = () => env.VAULT.getByName(VAULT_NAME);

function captureLogs() {
  const lines: string[] = [];
  for (const method of ["log", "info", "warn", "error", "debug", "trace"] as const) {
    vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
      lines.push(
        JSON.stringify(args, (_key, value: unknown) =>
          value instanceof Error ? { name: value.name, message: value.message, stack: value.stack } : value,
        ),
      );
    });
  }
  return {
    lines,
    expectNone(markers: readonly string[]) {
      const text = lines.join("\n");
      expect(markers.length).toBeGreaterThan(0);
      for (const marker of markers) expect(text).not.toContain(marker);
    },
  };
}

let clients: TestClient[] = [];

async function open() {
  const opened = await connect(SELF);
  clients.push(opened.client);
  return opened;
}

afterEach(async () => {
  vi.restoreAllMocks();
  for (const client of clients) client.close();
  clients = [];
  await vault().closeAllConnections();
});

describe("DATA-1: log redaction", () => {
  it("logs nothing from AUTH, REQ, EVENT and their failures", async () => {
    const stored = signVerified({ kind: 1, created_at: 100, content: CONTENT, tags: [["t", FILTER]] }, KEY_OWNER);
    await runInDurableObject(vault(), (_instance, state) => {
      const opened = EventStore.open(state.storage, testConfig(publicKeyOf(KEY_OWNER)), 0);
      if (!opened.ok) throw new Error(opened.error);
      opened.store.apply(stored, 200);
    });
    const logs = captureLogs();
    const { client, challenge } = await open();
    const markers = [CONTENT, FILTER, stored.id, stored.sig];
    const auths = [
      authEvent(KEY_STRANGER, challenge, { content: CONTENT }),
      authEvent(KEY_OWNER, "another challenge", { content: CONTENT }),
      { ...authEvent(KEY_OWNER, challenge, { content: CONTENT }), sig: stored.sig },
      authEvent(KEY_OWNER, challenge, { content: CONTENT.repeat(20_000) }),
      authEvent(KEY_OWNER, challenge, { content: CONTENT }),
    ];
    for (const auth of auths) {
      markers.push(auth.id, auth.sig);
      client.send(["AUTH", auth]);
    }
    client.send(["REQ", "sub", { "#t": [FILTER] }]);
    client.send(["REQ", "bad", { [`#${FILTER}`]: [FILTER] }]);
    client.send(["EVENT", stored]);
    client.ws.send(`["AUTH", ${CONTENT}`);
    client.ws.send(`["REQ","${FILTER.repeat(25_000)}"]`);
    client.ws.send(new TextEncoder().encode(CONTENT));
    const received = await client.drain();
    // The paths ran: the owner's REQ returned the stored event.
    expect(received).toContainEqual(["EVENT", "sub", stored]);
    logs.expectNone(markers);
    expect(logs.lines).toEqual([]);
  });

  it("logs a failed message by error class only", async () => {
    const { client, challenge } = await open();
    const logs = captureLogs();
    // The relay's answer to AUTH fails with a message full of secrets; the client's own sends go through.
    const original: unknown = Object.getOwnPropertyDescriptor(WebSocket.prototype, "send")?.value;
    if (typeof original !== "function") throw new Error("WebSocket.prototype.send is not a method");
    vi.spyOn(WebSocket.prototype, "send").mockImplementation(function (this: WebSocket, message) {
      if (typeof message === "string" && message.startsWith('["OK"')) {
        throw new Error(`${ERROR} ${CONTENT} ${message}`);
      }
      Reflect.apply(original, this, [message]);
    });
    const auth = authEvent(KEY_OWNER, challenge, { content: CONTENT });
    client.send(["AUTH", auth]);
    expect(await client.closed).toEqual({ code: 1011, reason: "error: internal error" });
    logs.expectNone([ERROR, CONTENT, auth.id, auth.sig]);
    expect(logs.lines).toEqual(['["{\\"event\\":\\"zenith.message.failed\\",\\"error\\":\\"Error\\"}"]']);
  });
});
