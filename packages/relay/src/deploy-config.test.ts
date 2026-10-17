import { describe, expect, it } from "vitest";
import { DeployConfigError, mergeDeployConfig, parseJsonc, splitArgs } from "../scripts/deploy-config.ts";

// DATA-2: the deployment file sets only the deployment values, none of them secret, and the route is the relay's.
const BASE = {
  $schema: "./node_modules/wrangler/config-schema.json",
  name: "zenith-relay",
  main: "src/index.ts",
  r2_buckets: [{ binding: "BACKUPS" }],
  triggers: { crons: ["17 3 * * *"] },
};
const OWNER = "0".repeat(64);

function deployFile(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    routes: [{ pattern: "relay.example.com", custom_domain: true }],
    r2_buckets: [{ binding: "BACKUPS", bucket_name: "backup-bucket" }],
    vars: { OWNER_PUBKEY: OWNER, RELAY_URL: "wss://relay.example.com/" },
    ...overrides,
  };
}

function refusal(deploy: unknown): string {
  try {
    mergeDeployConfig(BASE, deploy, "../../src/index.ts");
  } catch (error) {
    if (error instanceof DeployConfigError) return error.message;
    throw error;
  }
  return "accepted";
}

describe("mergeDeployConfig", () => {
  it("merges the deployment values into the public configuration", () => {
    expect(mergeDeployConfig(BASE, deployFile({ account_id: "a".repeat(32) }), "../../src/index.ts")).toEqual({
      name: "zenith-relay",
      main: "../../src/index.ts",
      account_id: "a".repeat(32),
      triggers: { crons: ["17 3 * * *"] },
      routes: [{ pattern: "relay.example.com", custom_domain: true }],
      r2_buckets: [{ binding: "BACKUPS", bucket_name: "backup-bucket" }],
      vars: { OWNER_PUBKEY: OWNER, RELAY_URL: "wss://relay.example.com/" },
    });
  });

  it.each([
    ["the relay's host as a route pattern", [{ pattern: "relay.example.com/*", zone_name: "example.com" }]],
    ["the relay's host as a string route", ["relay.example.com/*"]],
  ])("accepts %s", (_name, routes) => {
    expect(refusal(deployFile({ routes }))).toBe("accepted");
  });

  it.each([
    [
      "a custom domain with the relay host as a prefix",
      [{ pattern: "relay.example.com.other.example", custom_domain: true }],
    ],
    ["a custom domain on a subdomain", [{ pattern: "x.relay.example.com", custom_domain: true }]],
    ["a custom domain with a path", [{ pattern: "relay.example.com/x", custom_domain: true }]],
    ["a route on a host with the relay host as a prefix", [{ pattern: "relay.example.com.other.example/*" }]],
    ["a string route on another host", ["relay.example.community/*"]],
    ["a wildcard route", [{ pattern: "*relay.example.com/*" }]],
    ["a second route on another host", [{ pattern: "relay.example.com", custom_domain: true }, "other.example/*"]],
    ["no route", []],
  ])("refuses %s", (_name, routes) => {
    expect(refusal(deployFile({ routes }))).toContain("route");
  });

  it.each([
    ["another key", deployFile({ triggers: { crons: [] } }), 'may not set "triggers"'],
    [
      "a secret variable",
      deployFile({ vars: { OWNER_PUBKEY: OWNER, RELAY_URL: "wss://relay.example.com/", OWNER_NSEC: "x" } }),
      '"vars" must set exactly',
    ],
    [
      "an npub as the owner",
      deployFile({ vars: { OWNER_PUBKEY: "npub1x", RELAY_URL: "wss://relay.example.com/" } }),
      "OWNER_PUBKEY",
    ],
    [
      "a ws relay URL",
      deployFile({ vars: { OWNER_PUBKEY: OWNER, RELAY_URL: "ws://relay.example.com/" } }),
      "RELAY_URL",
    ],
    // The Worker refuses a relay URL with credentials (parseRelayConfig), so deploying one would leave it unavailable.
    [
      "a relay URL with credentials",
      deployFile({ vars: { OWNER_PUBKEY: OWNER, RELAY_URL: "wss://user:pass@relay.example.com/" } }),
      "RELAY_URL",
    ],
    [
      "an uppercase hex owner, which the Worker refuses",
      deployFile({ vars: { OWNER_PUBKEY: "A".repeat(64), RELAY_URL: "wss://relay.example.com/" } }),
      "OWNER_PUBKEY",
    ],
    ["a placeholder account id", deployFile({ account_id: "<ACCOUNT_ID>" }), "account_id"],
    [
      "a bucket for another binding",
      deployFile({ r2_buckets: [{ binding: "OTHER", bucket_name: "backup-bucket" }] }),
      "no R2 binding",
    ],
  ])("refuses %s", (_name, deploy, message) => {
    expect(refusal(deploy)).toContain(message);
  });

  it("reads the example deployment file as JSONC", () => {
    expect(parseJsonc('{ // a comment\n "a": "wss://x/", /* b */ "c": [1, 2,], }')).toEqual({
      a: "wss://x/",
      c: [1, 2],
    });
  });
});

describe("splitArgs", () => {
  it("gives the authentication options to every command and the rest to deploy", () => {
    expect(splitArgs(["--dry-run", "--profile", "work", "--outdir", "x", "--profile=other"])).toEqual({
      auth: ["--profile", "work", "--profile=other"],
      rest: ["--dry-run", "--outdir", "x"],
    });
  });

  it.each([["--config", "x"], ["-c", "x"], ["--config=x"]])("refuses %s", (...args) => {
    expect(() => splitArgs(args)).toThrow(DeployConfigError);
  });
});
