import type { VerifiedEvent } from "./event.ts";
import { DEFAULT_AUTH_LIMITS, type AuthLimits } from "./limits.ts";

export const AUTH_REJECTION_CODES = ["wrong-kind", "stale", "challenge-mismatch", "relay-mismatch"] as const;
export type AuthRejectionCode = (typeof AUTH_REJECTION_CODES)[number];

export type AuthRejection = {
  /**
   * A malformed AUTH event is an invalid message. NIP-42's `auth-required:` and `restricted:` answer a REQ or
   * EVENT that needs authentication, not the AUTH event itself.
   */
  prefix: "invalid";
  code: AuthRejectionCode;
  message: string;
};

export type AuthVerification = { ok: true; pubkey: string } | { ok: false; error: AuthRejection };

export type AuthOptions = {
  /** The challenge this connection was sent. */
  challenge: string;
  /** The configured relay URL, not the request's Host. */
  relayUrl: string;
  /** Current time in unix seconds. */
  now: number;
  limits?: Partial<AuthLimits>;
};

const AUTH_KIND = 22242;

const MESSAGES: Record<AuthRejectionCode, string> = {
  "wrong-kind": "AUTH event must be kind 22242",
  stale: "AUTH event created_at is too far from the current time",
  "challenge-mismatch": "AUTH event challenge does not match",
  "relay-mismatch": "AUTH event relay does not match this relay",
};

/**
 * Checks a NIP-42 AUTH event against this connection's challenge and the configured relay (RD-2).
 * The signature was checked when the event became a VerifiedEvent. Never throws.
 */
export function verifyAuthEvent(event: VerifiedEvent, options: AuthOptions): AuthVerification {
  const { maxClockSkewSeconds } = { ...DEFAULT_AUTH_LIMITS, ...options.limits };
  if (event.kind !== AUTH_KIND) return reject("wrong-kind");
  if (Math.abs(event.created_at - options.now) > maxClockSkewSeconds) return reject("stale");
  if (firstTagValue(event, "challenge") !== options.challenge) return reject("challenge-mismatch");
  const expected = relayHost(options.relayUrl);
  const actual = relayHost(firstTagValue(event, "relay") ?? "");
  if (expected === undefined || actual !== expected) return reject("relay-mismatch");
  return { ok: true, pubkey: event.pubkey };
}

function reject(code: AuthRejectionCode): AuthVerification {
  return { ok: false, error: { prefix: "invalid", code, message: MESSAGES[code] } };
}

function firstTagValue(event: VerifiedEvent, name: string): string | undefined {
  return event.tags.find((tag) => tag[0] === name)?.[1];
}

const DEFAULT_PORTS: Record<string, string> = { ws: ":80", wss: ":443" };

/**
 * The host (with a non-default port) of a ws or wss URL, lowercased; undefined for anything else.
 * NIP-42: "URL normalization techniques can be applied. For most cases just checking if the domain name is
 * correct should be enough." So the scheme (ws or wss), the path, the query and a trailing slash are ignored.
 */
function relayHost(url: string): string | undefined {
  const match = /^(wss?):\/\/([^/?#]*)/i.exec(url);
  const scheme = match?.[1]?.toLowerCase();
  const authority = match?.[2]?.toLowerCase();
  if (scheme === undefined || authority === undefined || authority === "" || authority.includes("@")) {
    return undefined;
  }
  const defaultPort = DEFAULT_PORTS[scheme];
  return defaultPort !== undefined && authority.endsWith(defaultPort)
    ? authority.slice(0, -defaultPort.length)
    : authority;
}
