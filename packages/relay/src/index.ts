/**
 * The relay Worker. RES-3: it answers every public HTTP request itself, NIP-11 included, and wakes the Vault DO only
 * for a WebSocket upgrade on the relay's path, an admin request the owner signed (OPS-1), and the backup cron
 * (DATA-5).
 */
import { adminRefusalResponse, adminResultResponse, authorizeAdminRequest } from "./admin.ts";
import { parseRelayConfig } from "./config.ts";
import { errorName, logEvent } from "./log.ts";
import { acceptsRelayInformation, CORS_HEADERS, relayInformationResponse } from "./nip11.ts";
import { VAULT_NAME, type BackupRunResult } from "./vault.ts";

export { Vault } from "./vault.ts";

export default {
  async fetch(request, env): Promise<Response> {
    const parsed = parseRelayConfig(env);
    if (!parsed.ok) {
      logEvent("zenith.config.invalid", { reason: parsed.error });
      return new Response("Unavailable", { status: 503 });
    }
    const { config } = parsed;
    // OPS-1: exactly the configured admin URL; the NIP-98 `u` tag must name it too.
    if (request.url === config.adminUrl) {
      const authorization = await authorizeAdminRequest(request, config, () => Math.floor(Date.now() / 1000));
      if (!authorization.ok) return adminRefusalResponse(authorization.refusal);
      try {
        return adminResultResponse(await env.VAULT.getByName(VAULT_NAME).admin(authorization.command));
      } catch (error) {
        logEvent("zenith.admin.failed", { error: errorName(error) });
        return new Response("Internal Error", { status: 500 });
      }
    }
    if (new URL(request.url).pathname !== config.path) return notFound();
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

  /** DATA-5: the daily backup. A failure is logged as a reason code only, and fails the invocation. */
  async scheduled(controller, env): Promise<void> {
    const parsed = parseRelayConfig(env);
    if (!parsed.ok) {
      logEvent("zenith.config.invalid", { reason: parsed.error });
      throw new Error("the configuration is invalid");
    }
    let result: BackupRunResult | undefined;
    try {
      result = await env.VAULT.getByName(VAULT_NAME).backup(controller.scheduledTime);
    } catch (error) {
      logEvent("zenith.backup.failed", { error: errorName(error) });
    }
    if (result?.ok === false) logEvent("zenith.backup.failed", { reason: result.error });
    // The error carries no cause: the log line above is the whole record of the failure (DATA-1).
    if (result?.ok !== true) throw new Error("the backup failed");
  },
} satisfies ExportedHandler<Env>;

function notFound(): Response {
  return new Response("Not Found", { status: 404 });
}
