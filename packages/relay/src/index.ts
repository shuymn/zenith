/**
 * The relay Worker. RES-3: it answers every public HTTP request itself, NIP-11 included, and passes only WebSocket
 * upgrades on the relay's path to the Vault DO.
 */
import { parseRelayConfig } from "./config.ts";
import { logEvent } from "./log.ts";
import { acceptsRelayInformation, CORS_HEADERS, relayInformationResponse } from "./nip11.ts";
import { VAULT_NAME } from "./vault.ts";

export { Vault } from "./vault.ts";

export default {
  async fetch(request, env): Promise<Response> {
    const parsed = parseRelayConfig(env);
    if (!parsed.ok) {
      logEvent("zenith.config.invalid", { reason: parsed.error });
      return new Response("Unavailable", { status: 503 });
    }
    if (new URL(request.url).pathname !== parsed.config.path) return notFound();
    const method = request.method;
    if (method === "GET" && request.headers.get("Upgrade")?.toLowerCase() === "websocket") {
      return env.VAULT.getByName(VAULT_NAME).fetch(request);
    }
    if (method === "OPTIONS") return new Response(null, { status: 204, headers: CORS_HEADERS });
    if ((method === "GET" || method === "HEAD") && acceptsRelayInformation(request)) {
      return relayInformationResponse();
    }
    return notFound();
  },
} satisfies ExportedHandler<Env>;

function notFound(): Response {
  return new Response("Not Found", { status: 404 });
}
