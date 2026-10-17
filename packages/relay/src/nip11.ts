/**
 * The NIP-11 relay information document, answered by the Worker without waking the DO (RES-3). RD-5: it discloses
 * the minimum, so it has no name, description, contact or `pubkey` (that would name the owner); only the NIPs and the
 * limits a client needs to talk to the relay.
 */
import { DEFAULT_CONNECTION_LIMITS, DEFAULT_EVENT_LIMITS, DEFAULT_FILTER_LIMITS } from "@zenith/core";

/** NIP-01: subscription ids are of "max length 64 chars". */
const MAX_SUBSCRIPTION_ID_LENGTH = 64;

const DOCUMENT = {
  supported_nips: [1, 9, 11, 40, 42, 70],
  limitation: {
    max_message_length: DEFAULT_CONNECTION_LIMITS.maxMessageBytes,
    max_subscriptions: DEFAULT_CONNECTION_LIMITS.maxSubscriptions,
    max_limit: DEFAULT_FILTER_LIMITS.maxLimit,
    max_subid_length: MAX_SUBSCRIPTION_ID_LENGTH,
    max_event_tags: DEFAULT_EVENT_LIMITS.maxTags,
    created_at_upper_limit: DEFAULT_EVENT_LIMITS.maxFutureSeconds,
    default_limit: DEFAULT_FILTER_LIMITS.maxLimit,
    // NIP-11: "Even if set to False, authentication may be required for specific actions." Writes need no AUTH
    // (WR-1); reads do (RD-1).
    auth_required: false,
    payment_required: false,
    // NIP-11: "This should only be set to `true` when users are expected to know the relay policy before trying to
    // write to it -- like belonging to a special pubkey-based whitelist".
    restricted_writes: true,
  },
} as const;

/**
 * NIP-11: "Relays MUST accept CORS requests by sending `Access-Control-Allow-Origin`, `Access-Control-Allow-Headers`,
 * and `Access-Control-Allow-Methods` headers."
 */
export const CORS_HEADERS: Readonly<Record<string, string>> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Accept",
  "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
};

/** NIP-11: a request "with an `Accept` header of `application/nostr+json`". */
export function acceptsRelayInformation(request: Request): boolean {
  const accept = request.headers.get("Accept") ?? "";
  return accept.split(",").some((range) => range.split(";")[0]?.trim().toLowerCase() === "application/nostr+json");
}

export function relayInformationResponse(): Response {
  return new Response(JSON.stringify(DOCUMENT), {
    headers: { ...CORS_HEADERS, "Content-Type": "application/nostr+json" },
  });
}
