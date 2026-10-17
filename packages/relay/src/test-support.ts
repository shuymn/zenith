// Helpers shared by the tests. Not exported from the package.
import { evictDurableObject, runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { expect } from "vitest";
import { readState, type ConnectionState } from "./connection.ts";
import { VAULT_NAME } from "./vault.ts";
import { parseVaultConfig, type VaultConfig } from "./allowlist.ts";
import { EventStore } from "./store.ts";
import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import {
  computeEventId,
  parseFilter,
  verifyEventObject,
  type Filter,
  type UnsignedEvent,
  type VerifiedEvent,
} from "@zenith/core";

/** A test-only secret key derived from a fixed label. */
export function testSecretKey(label: string): Uint8Array {
  return sha256(utf8ToBytes(`zenith test key ${label}`));
}

export function publicKeyOf(secretKey: Uint8Array): string {
  return bytesToHex(schnorr.getPublicKey(secretKey));
}

/** Signs the template and runs it through verification, the only way to obtain a VerifiedEvent. */
export function signVerified(template: Partial<UnsignedEvent>, secretKey: Uint8Array): VerifiedEvent {
  const unsigned: UnsignedEvent = {
    pubkey: publicKeyOf(secretKey),
    created_at: 1_700_000_000,
    kind: 1,
    tags: [],
    content: "",
    ...template,
  };
  const id = computeEventId(unsigned);
  const sig = bytesToHex(schnorr.sign(hexToBytes(id), secretKey, new Uint8Array(32)));
  const result = verifyEventObject({ ...unsigned, id, sig }, { now: unsigned.created_at });
  if (!result.ok) throw new Error(`test event failed verification: ${result.error.code}`);
  return result.event;
}

export function filterOf(value: unknown): Filter {
  const result = parseFilter(value);
  if (!result.ok) throw new Error(result.error.message);
  return result.filter;
}

/** A configuration whose owner is `owner`. */
export function testConfig(owner: string): VaultConfig {
  const result = parseVaultConfig({ OWNER_PUBKEY: owner });
  if (!result.ok) throw new Error(result.code);
  return result.config;
}

/** Opens a store owned by `owner` with these importers, each with its kinds. */
export function openStore(
  storage: DurableObjectStorage,
  owner: string,
  importers: readonly (readonly [string, readonly number[]])[] = [],
): EventStore {
  const opened = EventStore.open(storage, testConfig(owner), 0);
  if (!opened.ok) throw new Error(`could not open the store: ${opened.code}`);
  const { store } = opened;
  for (const [pubkey, kinds] of importers) {
    const result = store.addKey(pubkey, { role: "importer", kinds }, 0);
    if (!result.ok) throw new Error(`could not add an importer: ${result.code}`);
  }
  return store;
}

/** The relay URL the tests configure (vitest.config.ts). */
export const TEST_RELAY_URL = "wss://relay.example/";

type Received = readonly unknown[];

/** The client side of a WebSocket to the relay, with its messages queued in order. */
export class TestClient {
  readonly ws: WebSocket;
  /** Resolves with the close code and reason when the relay closes the connection. */
  readonly closed: Promise<{ code: number; reason: string }>;
  readonly #queue: string[] = [];
  readonly #waiting: ((message: string) => void)[] = [];

  constructor(ws: WebSocket) {
    this.ws = ws;
    ws.addEventListener("message", (event) => {
      const data = typeof event.data === "string" ? event.data : "<binary>";
      const waiter = this.#waiting.shift();
      if (waiter === undefined) this.#queue.push(data);
      else waiter(data);
    });
    this.closed = new Promise((resolve) => {
      ws.addEventListener("close", (event) => resolve({ code: event.code, reason: event.reason }));
    });
    ws.accept();
  }

  /** The next message as text. */
  nextText(timeoutMs = 2000): Promise<string> {
    const queued = this.#queue.shift();
    if (queued !== undefined) return Promise.resolve(queued);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("no message from the relay")), timeoutMs);
      this.#waiting.push((message) => {
        clearTimeout(timer);
        resolve(message);
      });
    });
  }

  /** The next message, parsed. */
  async next(timeoutMs?: number): Promise<Received> {
    const value: unknown = JSON.parse(await this.nextText(timeoutMs));
    if (!Array.isArray(value)) throw new Error("the relay sent a message that is not an array");
    return value;
  }

  /** Every message received before the relay answers a malformed message, which it answers with a NOTICE. */
  async drain(): Promise<Received[]> {
    this.ws.send("[");
    const received: Received[] = [];
    for (;;) {
      const message = await this.next();
      if (message[0] === "NOTICE" && message[1] === "invalid: message is not valid JSON") return received;
      received.push(message);
    }
  }

  send(value: unknown): void {
    this.ws.send(JSON.stringify(value));
  }

  close(): void {
    this.ws.close(1000, "done");
  }
}

/** Opens a WebSocket through the Worker and returns it with the challenge the relay sent first. */
export async function connect(
  fetcher: Fetcher,
  url = TEST_RELAY_URL.replace("wss:", "https:"),
): Promise<{ client: TestClient; challenge: string }> {
  const response = await fetcher.fetch(url, { headers: { Upgrade: "websocket" } });
  if (response.webSocket === null) throw new Error(`no WebSocket: ${response.status}`);
  const client = new TestClient(response.webSocket);
  const [type, challenge] = await client.next();
  if (type !== "AUTH" || typeof challenge !== "string") throw new Error("the relay did not send a challenge first");
  return { client, challenge };
}

/** A signed NIP-42 AUTH event as JSON text. */
export function authEvent(
  secretKey: Uint8Array,
  challenge: string,
  overrides: Partial<UnsignedEvent> = {},
  relay = TEST_RELAY_URL,
): VerifiedEvent {
  return signVerified(
    {
      kind: 22242,
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ["relay", relay],
        ["challenge", challenge],
      ],
      ...overrides,
    },
    secretKey,
  );
}

/** The Vault DO the Worker forwards upgrades to. */
export const vault = () => env.VAULT.getByName(VAULT_NAME);

/** Runs `callback` on an EventStore opened on the Vault DO's storage, as the DO opens it with `owner`. */
export function withStore<T>(owner: string, callback: (store: EventStore) => T): Promise<T> {
  return runInDurableObject(vault(), (_instance, state) => {
    const opened = EventStore.open(state.storage, testConfig(owner), 0);
    if (!opened.ok) throw new Error(opened.code);
    return callback(opened.store);
  });
}

/**
 * Evicts the Vault DO, keeping its hibernated WebSockets. The returned check, called once the connection has been
 * used again, confirms that another instance served it: an instance created by runInDurableObject cannot use the
 * storage for a WebSocket message, so the check runs last.
 */
export async function evict(): Promise<() => Promise<void>> {
  const before = await runInDurableObject(vault(), (instance) => new WeakRef(instance));
  await evictDurableObject(vault());
  return async () => {
    const after = await runInDurableObject(vault(), (instance) => instance);
    expect(before.deref()).not.toBe(after);
  };
}

/** The attachment state of every open connection; a connection without an attachment gives undefined. */
export function connectionStates(): Promise<(ConnectionState | undefined)[]> {
  return runInDurableObject(vault(), (_instance, state) => state.getWebSockets().map((ws) => readState(ws)));
}

/** The ids of every registered subscription, over every open connection. */
export async function subscriptionIds(): Promise<string[]> {
  return (await connectionStates()).flatMap(
    (state) => state?.subscriptions.map((subscription) => subscription.id) ?? [],
  );
}

/** The admin URL the tests configure: RELAY_URL with https and `admin` under its path. */
export const TEST_ADMIN_URL = "https://relay.example/admin";

export type AdminRequestOptions = {
  /** The signer; the owner by default. */
  key?: Uint8Array;
  /** The request URL; the admin URL by default. */
  url?: string;
  method?: string;
  /** The NIP-98 event's fields; the default tags name the admin URL, the method and the body's sha256. */
  event?: Partial<UnsignedEvent>;
  /** The Authorization header as it is sent; null sends none. */
  authorization?: string | null;
};

/** A signed NIP-98 Authorization header for a request with this body. */
export function nip98Header(body: string, options: AdminRequestOptions = {}): string {
  const method = options.method ?? "POST";
  const event = signVerified(
    {
      kind: 27235,
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ["u", TEST_ADMIN_URL],
        ["method", method],
        ["payload", bytesToHex(sha256(utf8ToBytes(body)))],
      ],
      ...options.event,
    },
    options.key ?? testSecretKey("owner"),
  );
  let binary = "";
  for (const byte of utf8ToBytes(JSON.stringify(event))) binary += String.fromCharCode(byte);
  return `Nostr ${btoa(binary)}`;
}

/** A request to the admin route with `command` as its JSON body, signed by the owner unless `options` say otherwise. */
export function adminRequest(
  command: unknown,
  options: AdminRequestOptions = {},
): Request<unknown, IncomingRequestCfProperties> {
  const body = typeof command === "string" ? command : JSON.stringify(command);
  const method = options.method ?? "POST";
  const authorization = options.authorization === undefined ? nip98Header(body, options) : options.authorization;
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (authorization !== null) headers["Authorization"] = authorization;
  return new Request<unknown, IncomingRequestCfProperties>(options.url ?? TEST_ADMIN_URL, {
    method,
    headers,
    ...(method === "GET" || method === "HEAD" ? {} : { body }),
  });
}
