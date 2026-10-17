/**
 * The checks of the Worker's two variables, shared by the Worker's configuration (allowlist.ts, config.ts) and the
 * deployment check (scripts/deploy-config.ts), so that a value deploy accepts is one the Worker accepts.
 */
import { isHex32 } from "@zenith/core";

/** `OWNER_PUBKEY`: the owner's public key as 64 lowercase hex characters; an npub is refused. */
export function isOwnerPubkey(value: unknown): value is string {
  return isHex32(value);
}

/**
 * `RELAY_URL`: a ws or wss URL without credentials, as a URL; undefined for anything else. The deployment check also
 * requires wss.
 */
export function parseRelayUrl(value: unknown): URL | undefined {
  if (typeof value !== "string" || !URL.canParse(value)) return undefined;
  const url = new URL(value);
  if ((url.protocol !== "ws:" && url.protocol !== "wss:") || url.username !== "" || url.password !== "") {
    return undefined;
  }
  return url;
}
