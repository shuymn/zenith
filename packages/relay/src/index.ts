import { DurableObject } from "cloudflare:workers";

/**
 * The Vault DO: the single SQLite-backed Durable Object that holds all relay state in an `EventStore` opened on
 * `ctx.storage`. The protocol that drives it comes with stage 3.
 */
export class Vault extends DurableObject<Env> {}

export default {
  // RES-3: the Worker answers HTTP itself; nothing here wakes the DO yet.
  fetch(): Response {
    return new Response("Not Found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;
