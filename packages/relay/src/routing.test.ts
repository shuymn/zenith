/**
 * The Worker's routes (routes.ts) match the configured URLs exactly: URL variants neither reach a route they should
 * not nor miss one they should.
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { reset } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import worker from "./index.ts";
import { adminRequest, nip98Header, TEST_ADMIN_URL } from "./test-support.ts";
import { Vault } from "./vault.ts";

const LIST = { op: "list" };
const NOSTR_JSON = { Accept: "application/nostr+json" };
// DATA-1: an error message that must not reach the console.
const MARKER = "zenith-dummy-routing-error";

beforeEach(async () => {
  await reset();
});

afterEach(() => {
  vi.restoreAllMocks();
});

type IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

/** A request as the Worker receives one. */
function incoming(input: RequestInfo | URL, init?: RequestInit<IncomingRequestCfProperties>): IncomingRequest {
  return new Request<unknown, IncomingRequestCfProperties>(input, init);
}

type Sent = { readonly response: Response; readonly reachedVault: boolean };

/** Sends the request to the Worker and records whether it used the Vault namespace at all (RES-3). */
async function send(request: IncomingRequest): Promise<Sent> {
  const spies = [vi.spyOn(env.VAULT, "getByName"), vi.spyOn(env.VAULT, "get"), vi.spyOn(env.VAULT, "idFromName")];
  const response = await worker.fetch(request, env);
  const reachedVault = spies.some((spy) => spy.mock.calls.length > 0);
  for (const spy of spies) spy.mockRestore();
  return { response, reachedVault };
}

async function outcome(request: IncomingRequest): Promise<{ status: number; reachedVault: boolean }> {
  const { response, reachedVault } = await send(request);
  await response.arrayBuffer();
  return { status: response.status, reachedVault };
}

describe("OPS-1: the admin route is the configured admin URL exactly", () => {
  // Each request is signed by the owner for the configured admin URL, so reaching the admin route would answer 200.
  it.each([
    ["a trailing slash", "https://relay.example/admin/"],
    ["a double slash", "https://relay.example//admin"],
    ["a percent-encoded letter", "https://relay.example/%61dmin"],
    ["a percent-encoded slash", "https://relay.example/%2Fadmin"],
    ["another case", "https://relay.example/ADMIN"],
    ["a query", "https://relay.example/admin?op=list"],
    ["an empty query", "https://relay.example/admin?"],
    ["http instead of https", "http://relay.example/admin"],
    ["another host", "https://other.example/admin"],
    ["a host with the relay host as a prefix", "https://relay.example.other.example/admin"],
    ["another port", "https://relay.example:8443/admin"],
  ])("does not match %s, and answers 404 without the DO", async (_name, url) => {
    expect(await outcome(adminRequest(LIST, { url }))).toEqual({ status: 404, reachedVault: false });
  });

  // The runtime parses the URL before the Worker sees it; these normalize to the admin URL, as they always did.
  it.each([
    ["the admin URL", TEST_ADMIN_URL],
    ["an uppercase host", "https://RELAY.EXAMPLE/admin"],
    ["the default port", "https://relay.example:443/admin"],
    ["a dot segment", "https://relay.example/./admin"],
    ["a double-dot segment", "https://relay.example/x/../admin"],
    ["a percent-encoded dot segment", "https://relay.example/%2e/admin"],
  ])("matches %s", async (_name, url) => {
    expect(await outcome(adminRequest(LIST, { url }))).toEqual({ status: 200, reachedVault: true });
  });

  it("compares the NIP-98 u tag with the configured admin URL, not with the request's", async () => {
    // The request reaches the admin route (the runtime lowercases the host), but its u tag names the URL as sent.
    const url = "https://RELAY.EXAMPLE/admin";
    const body = JSON.stringify(LIST);
    const payload = ["payload", bytesToHex(sha256(utf8ToBytes(body)))];
    const authorization = nip98Header(body, { event: { tags: [["u", url], ["method", "POST"], payload] } });
    const { response, reachedVault } = await send(
      incoming(url, { method: "POST", body, headers: { Authorization: authorization } }),
    );
    expect({ status: response.status, body: await response.json(), reachedVault }).toEqual({
      status: 401,
      body: { ok: false, reason: "url-mismatch" },
      reachedVault: false,
    });
  });

  it("answers every method of the admin URL there: a GET upgrade does not reach the DO", async () => {
    const { response, reachedVault } = await send(incoming(TEST_ADMIN_URL, { headers: { Upgrade: "websocket" } }));
    expect({ status: response.status, allow: response.headers.get("Allow"), reachedVault }).toEqual({
      status: 405,
      allow: "POST",
      reachedVault: false,
    });
  });
});

describe("RES-3: the relay's path, and nothing else, answers NIP-11 and upgrades", () => {
  it.each([
    ["the relay URL", "https://relay.example/", 200],
    ["no path", "https://relay.example", 200],
    ["a query", "https://relay.example/?x=1", 200],
    // The relay's path is matched on any host, as it always was; the route decides which host reaches the Worker.
    ["another host", "https://other.example/", 200],
    ["a double slash", "https://relay.example//", 404],
    ["a percent-encoded slash", "https://relay.example/%2F", 404],
    ["another path", "https://relay.example/index.html", 404],
  ])("answers a NIP-11 request to %s (%s) with %i", async (_name, url, status) => {
    expect(await outcome(incoming(url, { headers: NOSTR_JSON }))).toEqual({ status, reachedVault: false });
  });

  // The runtime drops a HEAD response's body on the wire. Answering HEAD with the GET response, body included, leaves
  // every header the runtime derives from the body (Content-Length) to it, as for GET; an empty body would change them.
  it.each([
    ["NIP-11", incoming("https://relay.example/", { headers: NOSTR_JSON }), env],
    ["a 404", incoming("https://relay.example/other"), env],
    ["the admin route's 405", incoming(TEST_ADMIN_URL), env],
    ["a 503", incoming("https://relay.example/", { headers: NOSTR_JSON }), { ...env, OWNER_PUBKEY: "" }],
  ])("answers HEAD for %s with the status, headers and body of GET", async (_name, get, workerEnv) => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const head = incoming(get, { method: "HEAD" });
    const answers = await Promise.all(
      [get, head].map(async (request) => {
        const response = await worker.fetch(request, workerEnv);
        return { status: response.status, headers: Object.fromEntries(response.headers), body: await response.text() };
      }),
    );
    expect(answers[1]).toEqual(answers[0]);
    expect(answers[0]?.body).not.toBe("");
  });

  it.each([
    ["HEAD", "https://relay.example/"],
    ["POST", "https://relay.example/"],
    ["PUT", "https://relay.example/"],
    ["GET", "https://relay.example//"],
    ["GET", "https://relay.example/other"],
  ])("answers a %s upgrade to %s with 404, without the DO", async (method, url) => {
    const request = incoming(url, { method, headers: { Upgrade: "websocket" } });
    expect(await outcome(request)).toEqual({ status: 404, reachedVault: false });
  });

  it("matches a relay path below the root exactly, never percent-decoded", async () => {
    const vaultEnv = { ...env, RELAY_URL: "wss://relay.example/vault" };
    const status = async (url: string) => (await worker.fetch(incoming(url, { headers: NOSTR_JSON }), vaultEnv)).status;
    expect(await status("https://relay.example/vault")).toBe(200);
    expect(await status("https://relay.example/vault?x=1")).toBe(200);
    for (const url of [
      "https://relay.example/%76ault",
      "https://relay.example/vault/",
      "https://relay.example/VAULT",
      "https://relay.example/",
    ]) {
      expect({ url, status: await status(url) }).toEqual({ url, status: 404 });
    }
  });

  it("answers OPTIONS on another path with 404", async () => {
    const request = incoming("https://relay.example/other", { method: "OPTIONS" });
    expect(await outcome(request)).toEqual({ status: 404, reachedVault: false });
  });

  it("answers 404 with the same plain body and headers as before, without CORS headers", async () => {
    for (const request of [
      incoming("https://relay.example/"),
      incoming("https://relay.example/other", { headers: NOSTR_JSON }),
    ]) {
      const { response } = await send(request);
      expect({
        status: response.status,
        body: await response.text(),
        headers: Object.fromEntries(response.headers),
      }).toEqual({ status: 404, body: "Not Found", headers: { "content-type": "text/plain;charset=UTF-8" } });
    }
  });

  it("answers 503 with the same plain body as before when the configuration is invalid", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const response = await worker.fetch(incoming(TEST_ADMIN_URL, { method: "POST" }), { ...env, OWNER_PUBKEY: "" });
    expect({ status: response.status, body: await response.text() }).toEqual({ status: 503, body: "Unavailable" });
  });
});

describe("DATA-1: an error thrown on a route is not written to the console", () => {
  it("fails the request with the error, and logs nothing", async () => {
    const logs: unknown[][] = [];
    for (const method of ["log", "info", "warn", "error", "debug"] as const) {
      vi.spyOn(console, method).mockImplementation((...args: unknown[]) => logs.push(args));
    }
    vi.spyOn(Vault.prototype, "fetch").mockRejectedValueOnce(new TypeError(MARKER));
    const request = incoming("https://relay.example/", { headers: { Upgrade: "websocket" } });
    await expect(worker.fetch(request, env)).rejects.toThrow(MARKER);
    expect(logs).toEqual([]);
  });
});
