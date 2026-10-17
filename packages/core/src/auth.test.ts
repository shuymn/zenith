import { describe, expect, it } from "vitest";
import { verifyAuthEvent, type AuthRejectionCode, type AuthVerification } from "./auth.ts";
import type { NostrEvent, VerifiedEvent } from "./event.ts";
import { publicKeyOf, signVerified, testSecretKey } from "./test-support.ts";

const KEY = testSecretKey("auth");
const NOW = 1_700_000_000;
const CHALLENGE = "challenge-1234";
const RELAY_URL = "wss://relay.example.com/";

function authEvent(overrides: { kind?: number; created_at?: number; tags?: string[][] } = {}): VerifiedEvent {
  return signVerified(
    {
      kind: 22242,
      created_at: NOW,
      tags: [
        ["relay", RELAY_URL],
        ["challenge", CHALLENGE],
      ],
      ...overrides,
    },
    KEY,
  );
}

function verify(event: VerifiedEvent, options: { relayUrl?: string; now?: number } = {}): AuthVerification {
  return verifyAuthEvent(event, { challenge: CHALLENGE, relayUrl: RELAY_URL, now: NOW, ...options });
}

function codeOf(result: AuthVerification): AuthRejectionCode {
  if (result.ok) throw new Error("expected a rejection");
  expect(result.error.prefix).toBe("invalid");
  return result.error.code;
}

describe("verifyAuthEvent (RD-2)", () => {
  it("accepts a matching AUTH event and returns its pubkey", () => {
    expect(verify(authEvent())).toEqual({ ok: true, pubkey: publicKeyOf(KEY) });
  });

  it("accepts only VerifiedEvent", () => {
    const plain: NostrEvent = { ...authEvent() };
    // @ts-expect-error a NostrEvent that did not come from verification is not a VerifiedEvent
    expect(() => verifyAuthEvent(plain, { challenge: CHALLENGE, relayUrl: RELAY_URL, now: NOW })).not.toThrow();
  });

  // NIP-42: "that the `kind` is `22242`"
  it.each([1, 22241, 22243])("RD-2: rejects kind %i", (kind) => {
    expect(codeOf(verify(authEvent({ kind })))).toBe("wrong-kind");
  });

  // NIP-42: "that the event `created_at` is close (e.g. within ~10 minutes) of the current time"
  it.each([NOW - 600, NOW + 600])("RD-2: accepts created_at %i, within 600 seconds", (createdAt) => {
    expect(verify(authEvent({ created_at: createdAt })).ok).toBe(true);
  });

  it.each([NOW - 601, NOW + 601, NOW - 660])("RD-2: rejects created_at %i, beyond 600 seconds", (createdAt) => {
    expect(codeOf(verify(authEvent({ created_at: createdAt })))).toBe("stale");
  });

  // NIP-42: "that the `"challenge"` tag matches the challenge sent before"
  it.each([
    [
      "another challenge",
      [
        ["relay", RELAY_URL],
        ["challenge", "other"],
      ],
    ],
    [
      "a challenge prefix",
      [
        ["relay", RELAY_URL],
        ["challenge", CHALLENGE.slice(0, -1)],
      ],
    ],
    ["no challenge tag", [["relay", RELAY_URL]]],
    ["a challenge tag without a value", [["relay", RELAY_URL], ["challenge"]]],
    [
      "the challenge in a later tag only",
      [
        ["relay", RELAY_URL],
        ["challenge", "other"],
        ["challenge", CHALLENGE],
      ],
    ],
  ])("RD-2: rejects %s", (_name, tags) => {
    expect(codeOf(verify(authEvent({ tags })))).toBe("challenge-mismatch");
  });

  // NIP-42: "URL normalization techniques can be applied. For most cases just checking if the domain
  // name is correct should be enough."
  it.each([
    "wss://relay.example.com/",
    "wss://relay.example.com",
    "ws://relay.example.com",
    "WSS://Relay.Example.COM/",
    "wss://relay.example.com:443/",
    "wss://relay.example.com/some/path?x=1",
  ])("RD-2: accepts the relay tag %s", (relay) => {
    expect(
      verify(
        authEvent({
          tags: [
            ["relay", relay],
            ["challenge", CHALLENGE],
          ],
        }),
      ).ok,
    ).toBe(true);
  });

  it.each([
    ["another host", "wss://other.example.com/"],
    ["a subdomain", "wss://sub.relay.example.com/"],
    ["a host suffix", "wss://relay.example.com.evil.test/"],
    ["userinfo before another host", "wss://relay.example.com@evil.test/"],
    ["userinfo before the host", "wss://user@relay.example.com/"],
    ["another port", "wss://relay.example.com:8443/"],
    ["an http URL", "https://relay.example.com/"],
    ["no scheme", "relay.example.com"],
    ["an empty host", "wss:///"],
    ["no relay tag", undefined],
  ])("RD-2: rejects %s", (_name, relay) => {
    const tags =
      relay === undefined
        ? [["challenge", CHALLENGE]]
        : [
            ["relay", relay],
            ["challenge", CHALLENGE],
          ];
    expect(codeOf(verify(authEvent({ tags })))).toBe("relay-mismatch");
  });

  it("RD-2: compares against the configured relay URL", () => {
    const event = authEvent({
      tags: [
        ["relay", "wss://other.example.com"],
        ["challenge", CHALLENGE],
      ],
    });
    expect(verify(event, { relayUrl: "wss://other.example.com/" }).ok).toBe(true);
    expect(codeOf(verify(authEvent(), { relayUrl: "not a url" }))).toBe("relay-mismatch");
  });
});
