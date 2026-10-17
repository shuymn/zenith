/**
 * The state of one WebSocket connection, kept in its attachment so that it survives hibernation (RD-3). Nothing but
 * the attachment grants authentication: a connection without one, or with one that does not have this shape, is
 * unauthenticated and has no challenge.
 */

/** The platform refuses attachments over 16 KiB; the relay keeps 1 KiB of margin (RES-1). */
export const MAX_ATTACHMENT_BYTES = 15 * 1024;

export type Subscription = {
  readonly id: string;
  /** The filters as the client sent them, already accepted by parseFilters; parsed again where they are used. */
  readonly filters: readonly unknown[];
};

export type ConnectionState = {
  /** The challenge sent when the connection opened (RD-2); null without an attachment. */
  readonly challenge: string | null;
  /**
   * RES-4: when the relay closes the connection, in milliseconds since the epoch, unless it authenticates as a key
   * that may write; null once it has.
   */
  readonly deadline: number | null;
  /** Whether the connection completed AUTH with any key, listed or not (NIP-42's `restricted:` versus `auth-required:`). */
  readonly authenticated: boolean;
  /** The keys on the allowlist (owner or importer) this connection authenticated as. */
  readonly pubkeys: readonly string[];
  readonly subscriptions: readonly Subscription[];
};

/** The state of a connection without an attachment: unauthenticated, no challenge, past its deadline. */
export const UNATTACHED: ConnectionState = Object.freeze({
  challenge: null,
  deadline: 0,
  authenticated: false,
  pubkeys: [],
  subscriptions: [],
});

export function openedState(challenge: string, deadline: number): ConnectionState {
  return { challenge, deadline, authenticated: false, pubkeys: [], subscriptions: [] };
}

const VERSION = 1;
type Attachment = { readonly v: typeof VERSION } & ConnectionState;

/** The connection's state, or undefined when it has no attachment of this shape. */
export function readState(ws: WebSocket): ConnectionState | undefined {
  return parseAttachment(ws.deserializeAttachment());
}

/** Stores the state in the attachment; false, storing nothing, when it would exceed {@link MAX_ATTACHMENT_BYTES}. */
export function writeState(ws: WebSocket, state: ConnectionState): boolean {
  const attachment: Attachment = { v: VERSION, ...state };
  if (new TextEncoder().encode(JSON.stringify(attachment)).length > MAX_ATTACHMENT_BYTES) return false;
  ws.serializeAttachment(attachment);
  return true;
}

function parseAttachment(value: unknown): ConnectionState | undefined {
  if (!isRecord(value) || value.v !== VERSION) return undefined;
  const { challenge, deadline, authenticated, pubkeys, subscriptions } = value;
  if (typeof challenge !== "string" || typeof authenticated !== "boolean") return undefined;
  if (deadline !== null && typeof deadline !== "number") return undefined;
  if (!Array.isArray(pubkeys) || !pubkeys.every((pubkey) => typeof pubkey === "string")) return undefined;
  if (!Array.isArray(subscriptions)) return undefined;
  const parsed: Subscription[] = [];
  for (const subscription of subscriptions as unknown[]) {
    if (!isRecord(subscription) || typeof subscription.id !== "string" || !Array.isArray(subscription.filters)) {
      return undefined;
    }
    parsed.push({ id: subscription.id, filters: subscription.filters });
  }
  return { challenge, deadline, authenticated, pubkeys, subscriptions: parsed };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
