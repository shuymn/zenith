import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import type { NostrEvent, VerifiedEvent } from "@zenith/core";
import { createScheduledController, reset, runInDurableObject, SELF } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { authorizeAdminRequest, MAX_ADMIN_BODY_BYTES } from "./admin.ts";
import { parseRelayConfig } from "./config.ts";
import { backupKeys, readBackup, writeBackup } from "./backup-bucket.ts";
import worker from "./index.ts";
import { Vault } from "./vault.ts";
import {
  adminRequest,
  filterOf,
  nip98Header,
  openStore,
  publicKeyOf,
  signVerified,
  TEST_ADMIN_URL,
  testSecretKey,
  withStore,
} from "./test-support.ts";

const KEY_OWNER = testSecretKey("owner");
const KEY_STRANGER = testSecretKey("admin stranger");
const KEY_B = testSecretKey("admin B");
const KEY_C = testSecretKey("admin C");
const KEY_D = testSecretKey("admin D");
const OWNER = publicKeyOf(KEY_OWNER);
const B = publicKeyOf(KEY_B);
const C = publicKeyOf(KEY_C);
const D = publicKeyOf(KEY_D);
// DATA-1: a marker in event content that must reach neither a log line nor a response.
const CONTENT = "zenith-dummy-admin-content";

const LIST = { op: "list" };

beforeEach(async () => {
  await reset();
});

afterEach(() => {
  vi.restoreAllMocks();
});

async function send(
  request: Request<unknown, IncomingRequestCfProperties>,
  via: (request: Request<unknown, IncomingRequestCfProperties>) => Promise<Response> = (r) => SELF.fetch(r),
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await via(request);
  const text = await response.text();
  return { status: response.status, body: text.startsWith("{") ? JSON.parse(text) : { text } };
}

/**
 * RES-3: sends the request to the Worker with a Vault namespace that records every use, and expects none: the Worker
 * answered it without the DO.
 */
async function sendWithoutVault(request: Request<unknown, IncomingRequestCfProperties>): Promise<Response> {
  const calls = [vi.spyOn(env.VAULT, "getByName"), vi.spyOn(env.VAULT, "get"), vi.spyOn(env.VAULT, "idFromName")];
  const response = await worker.fetch(request, env);
  for (const spy of calls) expect(spy).not.toHaveBeenCalled();
  return response;
}

function ev(template: Partial<NostrEvent>, key: Uint8Array = KEY_OWNER): VerifiedEvent {
  return signVerified({ created_at: 1_700_000_000, content: CONTENT, ...template }, key);
}

/** Every object key in the backup bucket. */
async function bucketKeys(): Promise<string[]> {
  return (await env.BACKUPS.list()).objects.map((object) => object.key);
}

function now(): number {
  return Math.floor(Date.now() / 1000);
}

describe("OPS-1: the admin route is the owner's alone", () => {
  it("answers the owner's signed request", async () => {
    const { status, body } = await send(adminRequest(LIST));
    expect(status).toBe(200);
    expect(body).toEqual({
      ok: true,
      op: "list",
      allowlist: { keys: [{ pubkey: OWNER, role: "owner", addedAt: expect.any(Number) }], revoked: [] },
    });
  });

  // RES-3: none of these wakes the DO; the Worker answers each before calling it.
  it.each([
    ["no Authorization header", () => adminRequest(LIST, { authorization: null }), "missing"],
    ["another scheme", () => adminRequest(LIST, { authorization: "Bearer x" }), "bad-scheme"],
    ["a request signed by another key", () => adminRequest(LIST, { key: KEY_STRANGER }), "not-owner"],
    [
      "a u tag naming another URL",
      () =>
        adminRequest(LIST, {
          event: { tags: [["u", "https://evil.example/admin"], ["method", "POST"], payloadTag(LIST)] },
        }),
      "url-mismatch",
    ],
    [
      "a u tag naming the relay URL",
      () =>
        adminRequest(LIST, { event: { tags: [["u", "wss://relay.example/"], ["method", "POST"], payloadTag(LIST)] } }),
      "url-mismatch",
    ],
    [
      "a method tag of GET",
      () => adminRequest(LIST, { event: { tags: [["u", TEST_ADMIN_URL], ["method", "GET"], payloadTag(LIST)] } }),
      "method-mismatch",
    ],
    ["a time 61 seconds old", () => adminRequest(LIST, { event: { created_at: now() - 61 } }), "stale"],
    ["a time 10 minutes old", () => adminRequest(LIST, { event: { created_at: now() - 600 } }), "stale"],
    ["a time 61 seconds ahead", () => adminRequest(LIST, { event: { created_at: now() + 61 } }), "stale"],
    ["another kind", () => adminRequest(LIST, { event: { kind: 22242 } }), "wrong-kind"],
    [
      "no payload tag",
      () =>
        adminRequest(LIST, {
          event: {
            tags: [
              ["u", TEST_ADMIN_URL],
              ["method", "POST"],
            ],
          },
        }),
      "payload-missing",
    ],
    [
      "a body other than the signed one",
      () => adminRequest({ op: "backup" }, { authorization: nip98Header(JSON.stringify(LIST)) }),
      "payload-mismatch",
    ],
  ])("refuses %s with 401, without the DO", async (_name, request, reason) => {
    const response = await sendWithoutVault(request());
    expect(response.status).toBe(401);
    expect(response.headers.get("WWW-Authenticate")).toBe("Nostr");
    expect(await response.json()).toEqual({ ok: false, reason });
  });

  it("refuses a signature that does not verify with 401, without the DO", async () => {
    const header = nip98Header(JSON.stringify(LIST));
    const event: Record<string, unknown> = JSON.parse(atob(header.slice("Nostr ".length)));
    const forged = `Nostr ${btoa(JSON.stringify({ ...event, created_at: Number(event["created_at"]) + 1 }))}`;
    const response = await sendWithoutVault(adminRequest(LIST, { authorization: forged }));
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ ok: false, reason: "bad-event" });
  });

  it("reads the time after the body has arrived, so a body sent 61 seconds late is refused", async () => {
    const body = JSON.stringify(LIST);
    const signedAt = now();
    let clock = signedAt;
    const late = new ReadableStream<Uint8Array>(
      {
        pull(controller) {
          // The body arrives 61 seconds after the request was signed and sent.
          clock = signedAt + 61;
          controller.enqueue(new TextEncoder().encode(body));
          controller.close();
        },
        // Nothing is pulled before the body is read.
      },
      { highWaterMark: 0 },
    );
    const signed = adminRequest(LIST, { event: { created_at: signedAt } });
    const request = new Request(signed.url, { method: "POST", headers: signed.headers, body: late });
    const config = parseRelayConfig(env);
    if (!config.ok) throw new Error(config.code);
    expect(await authorizeAdminRequest(request, config.config, () => clock)).toEqual({
      ok: false,
      refusal: { status: 401, reason: "stale" },
    });
    // The same request with its body on time is accepted.
    clock = signedAt;
    const onTime = adminRequest(LIST, { event: { created_at: signedAt } });
    expect((await authorizeAdminRequest(onTime, config.config, () => clock)).ok).toBe(true);
  });

  it("answers another method with 405 and an oversized body with 413, without the DO", async () => {
    expect((await send(adminRequest(LIST, { method: "GET" }), sendWithoutVault)).status).toBe(405);
    expect((await send(adminRequest(LIST, { method: "PUT" }), sendWithoutVault)).status).toBe(405);
    const big = JSON.stringify({ op: "list", pad: "x".repeat(MAX_ADMIN_BODY_BYTES) });
    expect(await send(adminRequest(big), sendWithoutVault)).toEqual({
      status: 413,
      body: { ok: false, reason: "too-large" },
    });
  });

  it("answers the admin path on another URL as any other path, without the DO", async () => {
    for (const url of [`${TEST_ADMIN_URL}?x=1`, `${TEST_ADMIN_URL}/`, "https://other.example/admin"]) {
      expect(
        (
          await send(
            adminRequest(LIST, { url, event: { tags: [["u", url], ["method", "POST"], payloadTag(LIST)] } }),
            sendWithoutVault,
          )
        ).status,
      ).toBe(404);
    }
  });

  it.each([
    ["an unknown operation", { op: "delete" }],
    ["an extra field", { op: "list", pubkey: B }],
    ["a malformed pubkey", { op: "retire", pubkey: B.toUpperCase() }],
    ["kinds that are not numbers", { op: "add", pubkey: B, kinds: ["1"] }],
    ["a missing backup id", { op: "restore" }],
    ["JSON that is not an object", [LIST]],
    ["text that is not JSON", "op=list"],
  ])("answers the owner's signed request with %s with 400, without the DO", async (_name, command) => {
    expect(await send(adminRequest(command), sendWithoutVault)).toEqual({
      status: 400,
      body: { ok: false, reason: "bad-command" },
    });
  });
});

describe("OPS-1, DATA-4: allowlist operations", () => {
  it("adds, retires and revokes an importer, and refuses what the store refuses", async () => {
    const add = { op: "add", pubkey: B, kinds: [5, 1] };
    expect(await send(adminRequest(add))).toEqual({ status: 200, body: { ok: true, op: "add", connectionsClosed: 0 } });
    expect(await send(adminRequest(add))).toEqual({
      status: 409,
      body: { ok: false, op: "add", reason: "already-listed" },
    });
    expect((await send(adminRequest({ op: "add", pubkey: C, kinds: [62] }))).body).toMatchObject({
      reason: "bad-kinds",
    });
    expect((await send(adminRequest({ op: "add", pubkey: OWNER, kinds: [1] }))).body).toMatchObject({
      reason: "owner-key",
    });
    expect((await send(adminRequest({ op: "retire", pubkey: B }))).status).toBe(200);
    expect((await send(adminRequest({ op: "retire", pubkey: B }))).body).toMatchObject({ reason: "unchanged" });
    expect((await send(adminRequest({ op: "revoke", pubkey: OWNER }))).body).toMatchObject({ reason: "owner-key" });
    expect((await send(adminRequest({ op: "revoke", pubkey: B }))).status).toBe(200);
    expect((await send(adminRequest({ op: "add", pubkey: B, kinds: [1] }))).body).toMatchObject({
      reason: "revoked-key",
    });
    const { body } = await send(adminRequest(LIST));
    expect(body).toMatchObject({
      allowlist: { keys: [{ pubkey: OWNER, role: "owner" }], revoked: [{ pubkey: B }] },
    });
    // The state is the store's, not only the answer.
    await withStore(OWNER, (store) => {
      expect(store.roleOf(B)).toBeUndefined();
      expect(store.addKey(B, { role: "importer", kinds: [1] }, 0)).toEqual({ ok: false, code: "revoked-key" });
    });
  });
});

describe("DATA-5: backups", () => {
  it("writes the events, the allowlist and a manifest under a new key on each cron run", async () => {
    const note = ev({ kind: 1 });
    await withStore(OWNER, (store) => {
      store.addKey(B, { role: "importer", kinds: [1] }, 0);
      expect(store.apply(note, 1_700_000_000)).toEqual({ ok: true, outcome: "stored" });
    });
    const scheduledTime = Date.UTC(2026, 9, 18, 3, 17);
    for (let run = 0; run < 2; run++) {
      await worker.scheduled(createScheduledController({ scheduledTime }), env);
    }
    const keys = await bucketKeys();
    expect(keys).toHaveLength(6);
    const ids = [...new Set(keys.map((key) => key.split("/")[1]))];
    expect(ids).toHaveLength(2);
    for (const id of ids) {
      expect(id).toMatch(/^2026-10-18T03-17-00\.000Z-[0-9a-f]{16}$/);
      const objects = backupKeys(id ?? "");
      expect(keys).toEqual(expect.arrayContaining([objects.events, objects.allowlist, objects.manifest]));
      const exported = await withStore(OWNER, (store) => store.export());
      // Byte for byte the stored canonical JSON (ST-7), one line each.
      expect(await (await env.BACKUPS.get(objects.events))?.text()).toBe(`${exported.events.join("\n")}\n`);
      expect(await (await env.BACKUPS.get(objects.allowlist))?.text()).toBe(exported.allowlist);
      const manifest = await (await env.BACKUPS.get(objects.manifest))?.json();
      expect(manifest).toEqual({
        version: 1,
        id,
        created_at: "2026-10-18T03:17:00.000Z",
        events: {
          key: objects.events,
          sha256: expect.stringMatching(/^[0-9a-f]{64}$/),
          bytes: expect.any(Number),
          count: 1,
        },
        allowlist: {
          key: objects.allowlist,
          sha256: expect.stringMatching(/^[0-9a-f]{64}$/),
          bytes: expect.any(Number),
        },
      });
    }
  });

  it("writes a backup on the owner's request and names it", async () => {
    const { status, body } = await send(adminRequest({ op: "backup" }));
    expect(status).toBe(200);
    expect(body).toEqual({ ok: true, op: "backup", id: expect.stringMatching(/^\d{4}-/), events: 0 });
    const read = await readBackup(env.BACKUPS, body["id"]);
    expect(read.ok && read.backup.events).toEqual([]);
  });

  it("refuses a backup whose objects do not match its manifest, or that has none", async () => {
    const written = await writeBackup(env.BACKUPS, { events: [JSON.stringify(ev({}))], allowlist: "{}" }, Date.now());
    if (!written.ok) throw new Error(written.code);
    const keys = backupKeys(written.id);
    expect((await readBackup(env.BACKUPS, written.id)).ok).toBe(true);
    // Locally the bucket has no lock, so an object can be replaced; a restore must notice.
    await env.BACKUPS.put(keys.events, `${JSON.stringify(ev({ content: "other" }))}\n`);
    expect(await readBackup(env.BACKUPS, written.id)).toEqual({ ok: false, code: "integrity-mismatch" });
    await env.BACKUPS.delete(keys.manifest);
    expect(await readBackup(env.BACKUPS, written.id)).toEqual({ ok: false, code: "not-found" });
    for (const id of ["../x", "", `${written.id}/../x`, 1]) {
      expect(await readBackup(env.BACKUPS, id)).toEqual({ ok: false, code: "bad-backup-id" });
    }
  });

  it("logs a failed cron run as a reason code only, and fails the run", async () => {
    const logs: unknown[][] = [];
    vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => logs.push(args));
    const backup = vi.spyOn(Vault.prototype, "backup").mockResolvedValueOnce({ ok: false, code: "write-failed" });
    await expect(worker.scheduled(createScheduledController(), env)).rejects.toThrow("the backup failed");
    backup.mockRejectedValueOnce(new TypeError(CONTENT));
    await expect(worker.scheduled(createScheduledController(), env)).rejects.toThrow("the backup failed");
    expect(backup).toHaveBeenCalledTimes(2);
    expect(logs).toEqual([
      ['{"event":"zenith.backup.failed","reason":"write-failed"}'],
      ['{"event":"zenith.backup.failed","error":"TypeError"}'],
    ]);
  });

  it("returns write-failed when the bucket refuses a write, and writes no manifest", async () => {
    const put = vi.spyOn(env.BACKUPS, "put").mockRejectedValue(new Error(CONTENT));
    expect(await writeBackup(env.BACKUPS, { events: [], allowlist: "{}" }, Date.now())).toEqual({
      ok: false,
      code: "write-failed",
    });
    expect(put).toHaveBeenCalled();
    const puts = put.mock.calls.map(([key]) => key);
    expect(puts.some((key) => key.endsWith("manifest.json"))).toBe(false);
  });
});

/** A production backup: written by another Vault DO's backup method, from a vault with every kind of key. */
async function productionBackup() {
  const source = env.VAULT.get(env.VAULT.newUniqueId());
  const events = [
    ev({ kind: 1 }),
    ev({ kind: 0, created_at: 100 }),
    ev({ kind: 0, created_at: 200 }),
    ev({ kind: 1 }, KEY_B),
    ev({ kind: 1, tags: [["-"]] }, KEY_D),
  ];
  const expected = await runInDurableObject(source, (_instance, state) => {
    const store = openStore(state.storage, OWNER, [
      [B, [1]],
      [C, [1]],
      [D, [1]],
    ]);
    for (const event of events) expect(store.apply(event, 1_700_000_000).ok).toBe(true);
    expect(store.retireKey(B)).toEqual({ ok: true });
    expect(store.revokeKey(C, 5)).toEqual({ ok: true });
    return {
      keys: store.listKeys(),
      all: store.query([filterOf({})], 1_700_000_000),
      byIds: store.canonicalEvents(),
    };
  });
  const written = await source.backup(Date.now());
  if (!written.ok) throw new Error(written.code);
  return { id: written.id, expected };
}

describe("ST-6, ST-8: restore through the admin route", () => {
  it("restores a production backup, a retired key and its allowlist entry included, into an empty relay", async () => {
    const { id, expected } = await productionBackup();
    expect(await withStore(OWNER, (store) => store.canonicalEvents())).toEqual([]);
    const { status, body } = await send(adminRequest({ op: "restore", backup: id }));
    expect(status).toBe(200);
    expect(body).toEqual({ ok: true, op: "restore", events: 5, allowlistChanged: true, connectionsClosed: 0 });
    await withStore(OWNER, (store) => {
      expect(store.listKeys()).toEqual(expected.keys);
      expect(store.roleOf(B)).toBe("retired");
      expect(store.roleOf(C)).toBeUndefined();
      expect(store.query([filterOf({})], 1_700_000_000)).toEqual(expected.all);
      expect(store.canonicalEvents()).toEqual(expected.byIds);
      // ST-8: neither the retired nor the revoked key writes after the restore.
      expect(store.apply(ev({ kind: 1, created_at: 300 }, KEY_B), 1_700_000_000)).toEqual({
        ok: false,
        code: "retired-key",
      });
      expect(store.apply(ev({ kind: 1, created_at: 300 }, KEY_C), 1_700_000_000)).toEqual({
        ok: false,
        code: "unknown-key",
      });
    });
    // ST-6: a restore never merges into a vault that has events.
    expect(await send(adminRequest({ op: "restore", backup: id }))).toEqual({
      status: 409,
      body: { ok: false, op: "restore", reason: "not-empty" },
    });
  });

  it("refuses an unknown backup, a malformed id and a backup whose objects changed, restoring nothing", async () => {
    const { id } = await productionBackup();
    expect(
      (await send(adminRequest({ op: "restore", backup: "2026-01-01T00-00-00.000Z-0000000000000000" }))).status,
    ).toBe(404);
    expect((await send(adminRequest({ op: "restore", backup: "../../x" }))).body).toMatchObject({
      reason: "bad-backup-id",
    });
    await env.BACKUPS.put(backupKeys(id).allowlist, "{}");
    expect((await send(adminRequest({ op: "restore", backup: id }))).body).toMatchObject({
      reason: "integrity-mismatch",
    });
    expect(await withStore(OWNER, (store) => store.canonicalEvents())).toEqual([]);
  });

  it("DATA-1: logs nothing and answers no event content while backing up and restoring", async () => {
    const lines: string[] = [];
    for (const method of ["log", "info", "warn", "error", "debug", "trace"] as const) {
      vi.spyOn(console, method).mockImplementation((...args: unknown[]) => lines.push(JSON.stringify(args)));
    }
    const { id } = await productionBackup();
    const authorization = nip98Header(JSON.stringify({ op: "restore", backup: id }));
    const responses = [
      await SELF.fetch(adminRequest({ op: "restore", backup: id }, { authorization })),
      await SELF.fetch(adminRequest({ op: "restore", backup: id })),
      await SELF.fetch(adminRequest({ op: "backup" })),
      await SELF.fetch(adminRequest(LIST, { key: KEY_STRANGER })),
    ];
    const answered = await Promise.all(responses.map((response) => response.text()));
    expect(answered.join("")).toContain('"op"');
    const marker = authorization.slice("Nostr ".length, "Nostr ".length + 40);
    for (const text of [lines.join("\n"), answered.join("\n")]) {
      expect(text).not.toContain(CONTENT);
      expect(text).not.toContain(marker);
    }
    expect(lines).toEqual([]);
  });
});

function payloadTag(command: unknown): string[] {
  return ["payload", bytesToHex(sha256(utf8ToBytes(JSON.stringify(command))))];
}
