import { describe, expect, it } from "vitest";
import { parseRelayConfig } from "./config.ts";

const OWNER = "a".repeat(64);

describe("parseRelayConfig", () => {
  it("takes a ws or wss relay URL and its path", () => {
    const result = parseRelayConfig({ OWNER_PUBKEY: OWNER, RELAY_URL: "wss://relay.example/vault" });
    expect(result.ok && { relayUrl: result.config.relayUrl, path: result.config.path }).toEqual({
      relayUrl: "wss://relay.example/vault",
      path: "/vault",
    });
    const local = parseRelayConfig({ OWNER_PUBKEY: OWNER, RELAY_URL: "ws://localhost:8787" });
    expect(local.ok && local.config.path).toBe("/");
  });

  it.each([
    [undefined, "missing-relay-url"],
    ["", "missing-relay-url"],
    [42, "bad-relay-url"],
    ["relay.example", "bad-relay-url"],
    ["https://relay.example/", "bad-relay-url"],
    ["wss://user:pass@relay.example/", "bad-relay-url"],
  ])("refuses the relay URL %s", (url, error) => {
    expect(parseRelayConfig({ OWNER_PUBKEY: OWNER, RELAY_URL: url })).toEqual({ ok: false, error });
  });

  it("refuses a missing or malformed owner first", () => {
    expect(parseRelayConfig({ RELAY_URL: "wss://relay.example/" })).toEqual({ ok: false, error: "missing-owner" });
    expect(parseRelayConfig({ OWNER_PUBKEY: "A".repeat(64), RELAY_URL: "wss://relay.example/" })).toEqual({
      ok: false,
      error: "bad-owner",
    });
  });
});
