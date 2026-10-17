/**
 * The Vault DO: the single SQLite-backed Durable Object that holds all relay state in an `EventStore`, and the
 * WebSocket protocol on its connections. Connections use the hibernation API (RES-3), and each connection's state lives
 * in its attachment (RD-3).
 */
import {
  DEFAULT_CONNECTION_LIMITS,
  formatClosedMessage,
  formatNoticeMessage,
  formatOkMessage,
  parseClientMessage,
  parseFilters,
  verifyAuthEvent,
  verifyEvent,
  type ClientMessage,
} from "@zenith/core";
import { DurableObject } from "cloudflare:workers";
import type { KeyRole } from "./allowlist.ts";
import { parseRelayConfig, type RelayConfig } from "./config.ts";
import {
  openedState,
  readState,
  UNATTACHED,
  writeState,
  type ConnectionState,
  type Subscription,
} from "./connection.ts";
import { errorName, logEvent } from "./log.ts";
import { EventStore } from "./store.ts";

/** The fixed name of the one Vault DO. */
export const VAULT_NAME = "vault";

/** RES-4: a connection not authenticated as a key that may write is closed after this long. */
export const AUTH_TIMEOUT_MS = 30_000;

/**
 * An application-level ping answered by the runtime without waking the DO (RES-3). Nostr defines no ping message;
 * WebSocket protocol pings are answered by the runtime as well.
 */
export const PING = "ping";
export const PONG = "pong";

/** Close codes. 1008 is a policy violation; 1011 an unexpected condition; 1012 asks the client to reconnect. */
const CLOSE_AUTH_TIMEOUT = 1008;
const CLOSE_UNAVAILABLE = 1011;
const CLOSE_ALLOWLIST_CHANGED = 1012;
const AUTH_TIMEOUT_REASON = "auth-required: authentication timed out";

/** Whether authenticating as a key with this role lifts the RES-4 deadline: only keys that may write. */
const LIFTS_DEADLINE: Record<KeyRole, boolean> = { owner: true, importer: true, retired: false };

/** RD-1: how a REQ is answered by who the connection authenticated as. */
const READ_ACCESS = ["owner", "other-key", "unauthenticated"] as const;
type ReadAccess = (typeof READ_ACCESS)[number];
const READ_REFUSALS: Record<Exclude<ReadAccess, "owner">, string> = {
  // NIP-42: "for when a client has already performed `AUTH` but the key used to perform it is still not allowed".
  "other-key": "restricted: only the owner may read",
  // NIP-42: "for when a client has not performed `AUTH` and the relay requires that to fulfill the query".
  unauthenticated: "auth-required: authenticate as the owner to read",
};

type Opened = { readonly config: RelayConfig; readonly store: EventStore };

export class Vault extends DurableObject<Env> {
  // The store and the configuration, opened on first use; #opened is the only way to reach them.
  #state: Opened | undefined;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair(PING, PONG));
  }

  /** A WebSocket upgrade forwarded by the Worker; the only request the DO answers. */
  override async fetch(request: Request): Promise<Response> {
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return new Response("Expected a WebSocket upgrade", { status: 426 });
    }
    if (this.#opened() === undefined) return new Response("Unavailable", { status: 503 });
    const { 0: client, 1: server } = new WebSocketPair();
    this.ctx.acceptWebSocket(server);
    const challenge = randomChallenge();
    const deadline = Date.now() + AUTH_TIMEOUT_MS;
    writeState(server, openedState(challenge, deadline));
    // RD-2: "The relay sends a random challenge when the connection opens."
    server.send(JSON.stringify(["AUTH", challenge]));
    await this.#scheduleDeadline(deadline);
    return new Response(null, { status: 101, webSocket: client });
  }

  override async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    // A connection the relay already closed, or that is closing, gets nothing more.
    if (ws.readyState !== WebSocket.OPEN) return;
    // A connection without an attachment is unauthenticated (RD-3) and past its deadline.
    const state = readState(ws) ?? UNATTACHED;
    // RES-4: past the deadline nothing is verified, stored or logged, whether or not the client honored the close.
    if (isPastDeadline(state, Date.now())) {
      closeQuietly(ws, CLOSE_AUTH_TIMEOUT, AUTH_TIMEOUT_REASON);
      return;
    }
    try {
      this.#receive(ws, state, message);
    } catch (error) {
      logEvent("zenith.message.failed", { error: errorName(error) });
      closeQuietly(ws, CLOSE_UNAVAILABLE, "error: internal error");
    }
  }

  /** RES-4: closes the connections past their deadline, then schedules the next deadline. */
  override async alarm(): Promise<void> {
    const now = Date.now();
    let next: number | undefined;
    for (const ws of this.ctx.getWebSockets()) {
      const state = readState(ws) ?? UNATTACHED;
      if (state.deadline === null) continue;
      if (isPastDeadline(state, now)) closeQuietly(ws, CLOSE_AUTH_TIMEOUT, AUTH_TIMEOUT_REASON);
      else next = Math.min(next ?? state.deadline, state.deadline);
    }
    if (next !== undefined) await this.ctx.storage.setAlarm(next);
  }

  /**
   * OPS-2: closes every connection, so that no subscription keeps the authority it had before an allowlist change.
   * Returns the number of connections closed.
   */
  closeAllConnections(): number {
    const connections = this.ctx.getWebSockets();
    for (const ws of connections) closeQuietly(ws, CLOSE_ALLOWLIST_CHANGED, "the allowlist changed");
    return connections.length;
  }

  #receive(ws: WebSocket, state: ConnectionState, message: string | ArrayBuffer): void {
    if (typeof message !== "string") {
      sendNotice(ws, "invalid: binary messages are not accepted");
      return;
    }
    const parsed = parseClientMessage(message);
    if (!parsed.ok) {
      sendNotice(ws, formatNoticeMessage(parsed.error));
      return;
    }
    const opened = this.#opened();
    if (opened === undefined) {
      closeQuietly(ws, CLOSE_UNAVAILABLE, "error: the relay is unavailable");
      return;
    }
    this.#dispatch(ws, state, parsed.message, opened);
  }

  #dispatch(ws: WebSocket, state: ConnectionState, message: ClientMessage, opened: Opened): void {
    switch (message.type) {
      case "AUTH":
        this.#auth(ws, state, message.eventText, opened);
        return;
      case "REQ":
        this.#req(ws, state, message.subscriptionId, message.filters, opened);
        return;
      case "CLOSE":
        writeState(ws, withoutSubscription(state, message.subscriptionId));
        return;
      case "EVENT":
        sendNotice(ws, "unsupported: EVENT is not accepted yet");
        return;
      default:
        return message satisfies never;
    }
  }

  /** NIP-42 AUTH: RD-2 through verifyAuthEvent, on an event verified from its received text (EV-1). */
  #auth(ws: WebSocket, state: ConnectionState, eventText: string, { config, store }: Opened): void {
    const now = Math.floor(Date.now() / 1000);
    const verified = verifyEvent(eventText, { now });
    if (!verified.ok) {
      sendOk(ws, verified.error.eventId, false, formatOkMessage(verified.error));
      return;
    }
    const { event } = verified;
    if (state.challenge === null) {
      sendOk(ws, event.id, false, "invalid: this connection has no challenge");
      return;
    }
    const auth = verifyAuthEvent(event, { challenge: state.challenge, relayUrl: config.relayUrl, now });
    if (!auth.ok) {
      sendOk(ws, event.id, false, `${auth.error.prefix}: ${auth.error.message}`);
      return;
    }
    const role = store.roleOf(auth.pubkey);
    const allowed = role !== undefined && LIFTS_DEADLINE[role];
    const next: ConnectionState = allowed
      ? {
          ...state,
          authenticated: true,
          deadline: null,
          pubkeys: state.pubkeys.includes(auth.pubkey) ? state.pubkeys : [...state.pubkeys, auth.pubkey],
        }
      : { ...state, authenticated: true };
    if (!writeState(ws, next)) {
      sendOk(ws, event.id, false, "error: the connection state is full");
      return;
    }
    // RES-4: a key that is not allowed neither lifts nor extends the deadline.
    if (allowed) sendOk(ws, event.id, true, "");
    else sendOk(ws, event.id, false, "restricted: this key is not allowed here");
  }

  /** NIP-01 REQ, for the owner only (RD-1). A refused REQ is not registered and ends a subscription of the same id. */
  #req(
    ws: WebSocket,
    state: ConnectionState,
    subscriptionId: string,
    values: readonly unknown[],
    { config, store }: Opened,
  ): void {
    const others = withoutSubscription(state, subscriptionId);
    const refuse = (reason: string) => {
      if (others.subscriptions.length !== state.subscriptions.length) writeState(ws, others);
      sendClosed(ws, subscriptionId, reason);
    };
    const access = readAccess(state, config.vault.owner);
    if (access !== "owner") return refuse(READ_REFUSALS[access]);
    const filters = parseFilters(values);
    if (!filters.ok) return refuse(formatClosedMessage(filters.error));
    const { maxSubscriptions } = DEFAULT_CONNECTION_LIMITS;
    if (others.subscriptions.length >= maxSubscriptions) {
      return refuse(`invalid: more than ${maxSubscriptions} subscriptions`);
    }
    // NIP-01: a REQ with the same id replaces the subscription.
    const subscription: Subscription = { id: subscriptionId, filters: values };
    if (!writeState(ws, { ...others, subscriptions: [...others.subscriptions, subscription] })) {
      return refuse("invalid: the subscription does not fit in the connection state");
    }
    const prefix = `["EVENT",${JSON.stringify(subscriptionId)},`;
    for (const json of store.query(filters.filters, Math.floor(Date.now() / 1000))) ws.send(`${prefix}${json}]`);
    ws.send(JSON.stringify(["EOSE", subscriptionId]));
  }

  #opened(): Opened | undefined {
    if (this.#state !== undefined) return this.#state;
    const parsed = parseRelayConfig(this.env);
    if (!parsed.ok) {
      logEvent("zenith.config.invalid", { reason: parsed.error });
      return undefined;
    }
    const opened = EventStore.open(this.ctx.storage, parsed.config.vault, Math.floor(Date.now() / 1000));
    if (!opened.ok) {
      logEvent("zenith.store.unavailable", { reason: opened.error });
      return undefined;
    }
    this.#state = { config: parsed.config, store: opened.store };
    return this.#state;
  }

  /** Makes the alarm fire no later than `deadline` (RES-4). The DO keeps no resident timer (RES-3). */
  async #scheduleDeadline(deadline: number): Promise<void> {
    const current = await this.ctx.storage.getAlarm();
    if (current === null || current > deadline) await this.ctx.storage.setAlarm(deadline);
  }
}

/** RES-4: whether the connection is past its deadline at `now` (milliseconds). */
function isPastDeadline(state: ConnectionState, now: number): boolean {
  return state.deadline !== null && state.deadline <= now;
}

function readAccess(state: ConnectionState, owner: string): ReadAccess {
  if (state.pubkeys.includes(owner)) return "owner";
  return state.authenticated ? "other-key" : "unauthenticated";
}

function withoutSubscription(state: ConnectionState, id: string): ConnectionState {
  return { ...state, subscriptions: state.subscriptions.filter((subscription) => subscription.id !== id) };
}

/** 32 random bytes as lowercase hex. */
function randomChallenge(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** NIP-01: `["OK", <event_id>, <true|false>, <message>]`; without a well-formed id, a NOTICE instead. */
function sendOk(ws: WebSocket, eventId: string | undefined, accepted: boolean, message: string): void {
  if (eventId === undefined) sendNotice(ws, message);
  else ws.send(JSON.stringify(["OK", eventId, accepted, message]));
}

function sendClosed(ws: WebSocket, subscriptionId: string, message: string): void {
  ws.send(JSON.stringify(["CLOSED", subscriptionId, message]));
}

function sendNotice(ws: WebSocket, message: string): void {
  ws.send(JSON.stringify(["NOTICE", message]));
}

function closeQuietly(ws: WebSocket, code: number, reason: string): void {
  try {
    ws.close(code, reason);
  } catch {
    // Already closed.
  }
}
