/**
 * The Vault DO: the single SQLite-backed Durable Object that holds all relay state in an `EventStore`, and the
 * WebSocket protocol on its connections. Connections use the hibernation API (RES-3), and each connection's state lives
 * in its attachment (RD-3).
 */
import {
  canonicalEventJson,
  DEFAULT_CONNECTION_LIMITS,
  formatClosedMessage,
  formatNoticeMessage,
  formatOkMessage,
  parseClientMessage,
  matchesAnyFilter,
  parseFilters,
  referenceModel,
  verifyAuthEvent,
  verifyEvent,
  type ClientMessage,
  type VerifiedEvent,
} from "@zenith/core";
import { DurableObject } from "cloudflare:workers";
import type { AdminResult, AuthorizedCommand } from "./admin.ts";
import { toRejectionResponse, type AllowlistResult, type KeyRole } from "./allowlist.ts";
import { readBackup, writeBackup, type BackupWriteResult } from "./backup-bucket.ts";
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

/**
 * Which outcomes of a write are delivered live (RD-4): a stored event, and an ephemeral one, which is delivered and
 * never stored (WR-5). A version stored as history is not current, so a REQ without `ids` would not return it either.
 */
const DELIVERED: Record<referenceModel.ApplyOutcome, boolean> = {
  stored: true,
  "not-stored-ephemeral": true,
  "stored-as-history": false,
  duplicate: false,
  "rejected-deleted": false,
  "rejected-expired": false,
};

/** NIP-42: "Relays MUST exclude `kind: 22242` events from being broadcasted to any client." */
const AUTH_KIND = 22242;

/** WR-2, how a protected event from a connection not authenticated as its author is answered. */
const PROTECTED_REFUSALS: Record<Exclude<ReadAccess, "owner">, string> = {
  // NIP-70's example: `"auth-required: this event may only be published by its author"`.
  unauthenticated: "auth-required: this event may only be published by its author",
  "other-key": "restricted: this event may only be published by its author",
};

type Opened = { readonly config: RelayConfig; readonly store: EventStore };

/** The result of a backup run: written, or why not. */
export type BackupRunResult = BackupWriteResult | { readonly ok: false; readonly error: "unavailable" };

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

  /**
   * DATA-5: writes a backup of the vault to the backup bucket, as of now; `at` (milliseconds) names the run. Called by
   * the backup cron and by the admin route.
   */
  async backup(at: number): Promise<BackupRunResult> {
    const opened = this.#opened();
    if (opened === undefined) return { ok: false, error: "unavailable" };
    return writeBackup(this.env.BACKUPS, opened.store.export(), at);
  }

  /**
   * OPS-1: runs a command of the admin route, which the Worker authorized as the owner's. An allowlist change closes
   * every connection (OPS-2), and so does a restore that changed the allowlist.
   */
  async admin(command: AuthorizedCommand): Promise<AdminResult> {
    const opened = this.#opened();
    if (opened === undefined) return { ok: false, op: command.op, reason: "unavailable" };
    const { store } = opened;
    const now = Math.floor(Date.now() / 1000);
    switch (command.op) {
      case "list":
        return { ok: true, op: command.op, allowlist: store.listKeys() };
      case "add":
        return this.#allowlistChange(
          command.op,
          store.addKey(command.pubkey, { role: "importer", kinds: command.kinds }, now),
        );
      case "retire":
        return this.#allowlistChange(command.op, store.retireKey(command.pubkey));
      case "revoke":
        return this.#allowlistChange(command.op, store.revokeKey(command.pubkey, now));
      case "backup": {
        const result = await this.backup(Date.now());
        return result.ok
          ? { ok: true, op: command.op, id: result.id, events: result.events }
          : { ok: false, op: command.op, reason: result.error };
      }
      case "restore": {
        const read = await readBackup(this.env.BACKUPS, command.backup);
        if (!read.ok) return { ok: false, op: command.op, reason: read.error };
        // ST-6, ST-8: the store restores only into an empty vault and merges the allowlist.
        const result = store.restore(read.backup);
        if (!result.ok) return { ok: false, op: command.op, reason: result.error };
        const connectionsClosed = result.allowlistChanged ? this.closeAllConnections() : 0;
        return {
          ok: true,
          op: command.op,
          events: result.events,
          allowlistChanged: result.allowlistChanged,
          connectionsClosed,
        };
      }
      default:
        return command satisfies never;
    }
  }

  /** OPS-2: an allowlist operation that changed the allowlist closes every connection. */
  #allowlistChange(op: "add" | "retire" | "revoke", result: AllowlistResult): AdminResult {
    if (!result.changed) return { ok: false, op, reason: result.reason };
    return { ok: true, op, connectionsClosed: this.closeAllConnections() };
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
        this.#event(ws, state, message.eventText, opened);
        return;
      default:
        return message satisfies never;
    }
  }

  /**
   * NIP-01 EVENT: verified from its received text (EV-1, RES-1), checked for NIP-70 (WR-2), written by the store,
   * which checks the allowlist (WR-1, WR-3) and expiration (EV-6), and delivered live when stored or ephemeral.
   */
  #event(ws: WebSocket, state: ConnectionState, eventText: string, { config, store }: Opened): void {
    const now = Math.floor(Date.now() / 1000);
    const verified = verifyEvent(eventText, { now });
    if (!verified.ok) {
      sendOk(ws, verified.error.eventId, false, formatOkMessage(verified.error));
      return;
    }
    const { event } = verified;
    // WR-2. NIP-70: "The default behavior of a relay MUST be to reject any event that contains `["-"]`", unless the
    // client authenticated with "the same pubkey as the event being published".
    if (isProtected(event) && !state.pubkeys.includes(event.pubkey)) {
      sendOk(ws, event.id, false, PROTECTED_REFUSALS[state.authenticated ? "other-key" : "unauthenticated"]);
      return;
    }
    const result = store.apply(event, now);
    if (!result.ok) {
      const { message } = toRejectionResponse(result.rejection);
      sendOk(ws, event.id, false, message);
      return;
    }
    const { accepted, message } = referenceModel.toOkResponse(result.outcome);
    sendOk(ws, event.id, accepted, message);
    if (DELIVERED[result.outcome] && event.kind !== AUTH_KIND) this.#deliver(event, config.vault.owner);
  }

  /**
   * Live delivery (RD-4): to every open connection that is, at this moment, authenticated as the owner and within its
   * deadline, for each subscription whose filters match. An expired event is never delivered (ST-3). A connection
   * whose send fails is closed; the others still receive the event.
   */
  #deliver(event: VerifiedEvent, owner: string): void {
    const now = Date.now();
    if (referenceModel.isExpired(event, Math.floor(now / 1000))) return;
    const json = canonicalEventJson(event);
    for (const ws of this.ctx.getWebSockets()) {
      if (ws.readyState !== WebSocket.OPEN) continue;
      const state = readState(ws);
      if (state === undefined || isPastDeadline(state, now) || readAccess(state, owner) !== "owner") continue;
      for (const subscription of state.subscriptions) {
        const filters = parseFilters(subscription.filters);
        if (!filters.ok || !matchesAnyFilter(event, filters.filters)) continue;
        try {
          ws.send(`["EVENT",${JSON.stringify(subscription.id)},${json}]`);
        } catch (error) {
          logEvent("zenith.delivery.failed", { error: errorName(error) });
          closeQuietly(ws, CLOSE_UNAVAILABLE, "error: internal error");
          break;
        }
      }
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

/** NIP-70: "The tag is a simple tag with a single item: `["-"]`." A `-` tag with more items is treated alike. */
function isProtected(event: VerifiedEvent): boolean {
  return event.tags.some((tag) => tag[0] === "-");
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
