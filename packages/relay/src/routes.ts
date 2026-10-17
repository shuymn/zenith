/**
 * Which route of the Worker a request takes, by an exact check against the configuration; index.ts dispatches on it
 * with a `switch`. The URL is compared as the runtime parsed it: never percent-decoded, and the admin route includes
 * the scheme, the host and the absence of a query.
 */
import type { RelayConfig } from "./config.ts";

export const ROUTES = ["admin", "relay", "unmatched"] as const;
export type Route = (typeof ROUTES)[number];

/**
 * OPS-1: the admin route is exactly the configured admin URL, scheme, host and path, without a query. The relay route
 * is the relay's path, on any host, with any query. Both compare the URL as the runtime parsed it, never decoded.
 */
export function routeOf(request: Request, config: RelayConfig): Route {
  if (request.url === config.adminUrl) return "admin";
  return new URL(request.url).pathname === config.path ? "relay" : "unmatched";
}
