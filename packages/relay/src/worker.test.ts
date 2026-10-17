import { listDurableObjectIds, SELF } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import worker from "./index.ts";
import { publicKeyOf, testSecretKey } from "./test-support.ts";

const RELAY = "https://relay.example/";
const NOSTR_JSON = { Accept: "application/nostr+json" };

afterEach(() => {
  vi.restoreAllMocks();
});

async function expectNoDurableObject(): Promise<void> {
  expect(await listDurableObjectIds(env.VAULT)).toEqual([]);
}

describe("the Worker", () => {
  it("is configured with the test owner", () => {
    expect(env.OWNER_PUBKEY).toBe(publicKeyOf(testSecretKey("owner")));
  });

  describe("RD-5: NIP-11", () => {
    it("answers application/nostr+json with the minimal document and the limits", async () => {
      const response = await SELF.fetch(RELAY, { headers: NOSTR_JSON });
      expect(response.status).toBe(200);
      expect(response.headers.get("Content-Type")).toBe("application/nostr+json");
      expect(await response.json()).toEqual({
        supported_nips: [1, 9, 11, 40, 42, 70],
        limitation: {
          max_message_length: 524288,
          max_subscriptions: 20,
          max_limit: 500,
          max_subid_length: 64,
          max_event_tags: 2000,
          created_at_upper_limit: 900,
          default_limit: 500,
          auth_required: false,
          payment_required: false,
          restricted_writes: true,
        },
      });
    });

    it("does not disclose the owner's key", async () => {
      const response = await SELF.fetch(RELAY, { headers: NOSTR_JSON });
      expect(await response.text()).not.toContain(env.OWNER_PUBKEY);
    });

    it("sends the CORS headers NIP-11 requires, and answers a preflight", async () => {
      const response = await SELF.fetch(RELAY, { headers: { Accept: "text/html, application/nostr+json;q=0.9" } });
      await response.arrayBuffer();
      expect(response.status).toBe(200);
      for (const name of [
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Headers",
        "Access-Control-Allow-Methods",
      ]) {
        expect(response.headers.get(name)).not.toBeNull();
      }
      const preflight = await SELF.fetch(RELAY, { method: "OPTIONS" });
      expect(preflight.status).toBe(204);
      expect(preflight.headers.get("Access-Control-Allow-Origin")).toBe("*");
    });
  });

  describe("RES-3: public HTTP requests never reach the DO", () => {
    it.each([
      ["NIP-11", RELAY, { headers: NOSTR_JSON }, 200],
      ["a plain GET", RELAY, {}, 404],
      ["a POST", RELAY, { method: "POST", body: "[]" }, 404],
      ["another path", "https://relay.example/other", { headers: NOSTR_JSON }, 404],
      ["an upgrade on another path", "https://relay.example/other", { headers: { Upgrade: "websocket" } }, 404],
      // OPS-1: the admin route wakes the DO only for a request the owner signed.
      ["an unsigned admin request", "https://relay.example/admin", { method: "POST", body: '{"op":"list"}' }, 401],
      ["a GET of the admin route", "https://relay.example/admin", {}, 405],
    ] as const)("answers %s itself", async (_name, url, init, status) => {
      const response = await SELF.fetch(url, init);
      await response.arrayBuffer();
      expect(response.status).toBe(status);
      await expectNoDurableObject();
    });

    it("answers 503 without the DO when the configuration is invalid, logging only the reason", async () => {
      const logs: unknown[][] = [];
      vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => logs.push(args));
      const response = await worker.fetch(new Request(RELAY, { headers: NOSTR_JSON }), {
        ...env,
        RELAY_URL: "https://not-a-websocket.example/",
      });
      expect(response.status).toBe(503);
      expect(logs).toEqual([['{"event":"zenith.config.invalid","reason":"bad-relay-url"}']]);
      await expectNoDurableObject();
    });
  });
});
