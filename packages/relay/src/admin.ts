/**
 * The admin route (OPS-1): one URL under the relay's (`RelayConfig.adminUrl`) that takes a POST of one JSON command,
 * authorized by the owner's NIP-98 signature over that URL, the method and the body. The Worker checks all of it before
 * the Vault DO is woken (RES-3), and only {@link authorizeAdminRequest} creates the {@link AuthorizedCommand} that the
 * DO's `admin` method takes. Responses carry reason codes, keys and counts: never an event or a header.
 */
import {
  decodeUtf8Strict,
  isHex32,
  isRecord,
  parseJsonText,
  verifyHttpAuth,
  type HttpAuthRejectionCode,
} from "@zenith/core";
import { ALLOWLIST_REFUSALS, type AllowlistState } from "./allowlist.ts";
import { BACKUP_READ_ERRORS, BACKUP_WRITE_ERRORS } from "./backup-bucket.ts";
import type { RelayConfig } from "./config.ts";
import { RESTORE_ERRORS } from "./store.ts";

/** The largest admin request body. A command is a few hundred bytes; a restore names a backup, never carries one. */
export const MAX_ADMIN_BODY_BYTES = 4096;

export const ADMIN_OPERATIONS = ["list", "add", "retire", "revoke", "backup", "restore"] as const;
export type AdminOperation = (typeof ADMIN_OPERATIONS)[number];

export type AdminCommand =
  | { readonly op: "list" }
  | { readonly op: "add"; readonly pubkey: string; readonly kinds: readonly number[] }
  | { readonly op: "retire"; readonly pubkey: string }
  | { readonly op: "revoke"; readonly pubkey: string }
  | { readonly op: "backup" }
  /** `backup` is a backup id (`backups/<id>/` in the bucket); the DO reads the backup from R2 itself. */
  | { readonly op: "restore"; readonly backup: string };

export const ADMIN_COMMAND_ERRORS = ["bad-command"] as const;
export type AdminCommandError = (typeof ADMIN_COMMAND_ERRORS)[number];
export type AdminCommandParseResult =
  | { readonly ok: true; readonly command: AdminCommand }
  | { readonly ok: false; readonly code: AdminCommandError };

declare const authorized: unique symbol;
/** A command from a request that the owner signed with NIP-98; created only by {@link authorizeAdminRequest}. */
export type AuthorizedCommand = AdminCommand & { readonly [authorized]: true };

export const ADMIN_REFUSALS = [
  ...ALLOWLIST_REFUSALS,
  ...BACKUP_WRITE_ERRORS,
  ...BACKUP_READ_ERRORS,
  ...RESTORE_ERRORS,
  "unavailable",
] as const;
export type AdminRefusal = (typeof ADMIN_REFUSALS)[number];

export type AdminSuccess =
  | { readonly op: "list"; readonly allowlist: AllowlistState }
  /** OPS-2: every connection is closed when the allowlist changed. */
  | { readonly op: "add" | "retire" | "revoke"; readonly connectionsClosed: number }
  | { readonly op: "backup"; readonly id: string; readonly events: number }
  | {
      readonly op: "restore";
      readonly events: number;
      readonly allowlistChanged: boolean;
      readonly connectionsClosed: number;
    };

export type AdminResult =
  | ({ readonly ok: true } & AdminSuccess)
  | { readonly ok: false; readonly op: AdminOperation; readonly reason: AdminRefusal };

/** The status each refusal is answered with. */
const REFUSAL_STATUS: Record<AdminRefusal, number> = {
  "bad-pubkey": 400,
  "bad-kinds": 400,
  "bad-backup-id": 400,
  "owner-key": 409,
  "already-listed": 409,
  "revoked-key": 409,
  "not-listed": 409,
  unchanged: 409,
  "not-empty": 409,
  "owner-revoked": 409,
  "owner-retired": 409,
  "not-found": 404,
  "bad-manifest": 422,
  "integrity-mismatch": 422,
  "bad-allowlist": 422,
  "bad-event": 422,
  "write-failed": 502,
  unavailable: 503,
};

export type AdminRequestRefusal =
  | { readonly status: 401; readonly reason: HttpAuthRejectionCode | "not-owner" }
  | { readonly status: 400; readonly reason: AdminCommandError }
  | { readonly status: 405; readonly reason: "method-not-allowed" }
  | { readonly status: 413; readonly reason: "too-large" };

export type AdminAuthorization =
  | { readonly ok: true; readonly command: AuthorizedCommand }
  | { readonly ok: false; readonly refusal: AdminRequestRefusal };

/**
 * OPS-1: checks a request to the admin URL. In order: the method is POST, the body is at most
 * {@link MAX_ADMIN_BODY_BYTES}, the `Authorization` header is a NIP-98 event for the configured admin URL, this method
 * and this body (`verifyHttpAuth`), its signer is the configured owner, and the body is one command. `now` gives the
 * current time in unix seconds; it is read once the body has arrived, so a body sent late cannot extend the NIP-98
 * time window.
 */
export async function authorizeAdminRequest(
  request: Request,
  config: RelayConfig,
  now: () => number,
): Promise<AdminAuthorization> {
  if (request.method !== "POST") return refuse({ status: 405, reason: "method-not-allowed" });
  const body = await readBody(request, MAX_ADMIN_BODY_BYTES);
  if (body === undefined) return refuse({ status: 413, reason: "too-large" });
  const auth = verifyHttpAuth(request.headers.get("Authorization"), {
    url: config.adminUrl,
    method: request.method,
    body,
    now: now(),
  });
  if (!auth.ok) return refuse({ status: 401, reason: auth.code });
  if (auth.pubkey !== config.vault.owner) return refuse({ status: 401, reason: "not-owner" });
  const parsed = parseAdminCommand(body);
  if (!parsed.ok) return refuse({ status: 400, reason: parsed.code });
  // The one place that brands a command: its request was signed by the owner for this URL, method and body.
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion
  return { ok: true, command: parsed.command as AuthorizedCommand };
}

export function adminRefusalResponse(refusal: AdminRequestRefusal): Response {
  const headers: Record<string, string> = {};
  // RFC 7235: a 401 response "MUST send a WWW-Authenticate header field"; NIP-98's scheme is `Nostr`.
  if (refusal.status === 401) headers["WWW-Authenticate"] = "Nostr";
  if (refusal.status === 405) headers["Allow"] = "POST";
  return json({ ok: false, reason: refusal.reason }, refusal.status, headers);
}

export function adminResultResponse(result: AdminResult): Response {
  return json(result, result.ok ? 200 : REFUSAL_STATUS[result.reason]);
}

/** Parses one command. Every field is checked, and a field the command does not have refuses it. */
export function parseAdminCommand(body: Uint8Array): AdminCommandParseResult {
  const command = parseCommandFields(body);
  return command === undefined ? { ok: false, code: "bad-command" } : { ok: true, command };
}

function parseCommandFields(body: Uint8Array): AdminCommand | undefined {
  const text = decodeUtf8Strict(body);
  if (text === undefined) return undefined;
  const parsed = parseJsonText(text);
  if (!parsed.ok) return undefined;
  const { value } = parsed;
  if (!isRecord(value)) return undefined;
  const fields: Record<string, unknown> = { ...value };
  const op = fields["op"];
  const has = (...names: string[]) =>
    Object.keys(fields).length === names.length + 1 && names.every((name) => name in fields);
  const pubkey = fields["pubkey"];
  switch (op) {
    case "list":
    case "backup":
      return has() ? { op } : undefined;
    case "retire":
    case "revoke":
      return has("pubkey") && isHex32(pubkey) ? { op, pubkey } : undefined;
    case "add": {
      const kinds = fields["kinds"];
      if (!has("pubkey", "kinds") || !isHex32(pubkey) || !Array.isArray(kinds)) {
        return undefined;
      }
      const values: unknown[] = kinds;
      // The store checks the kinds of a grant (WR-1, WR-3); only their type is checked here.
      if (!values.every((kind): kind is number => typeof kind === "number")) return undefined;
      return { op, pubkey, kinds: values };
    }
    case "restore": {
      const backup = fields["backup"];
      return has("backup") && typeof backup === "string" ? { op, backup } : undefined;
    }
    default:
      return undefined;
  }
}

function refuse(refusal: AdminRequestRefusal): AdminAuthorization {
  return { ok: false, refusal };
}

/** The body, or undefined when it is longer than `max` bytes; reading stops there. */
async function readBody(request: Request, max: number): Promise<Uint8Array | undefined> {
  const declared = request.headers.get("Content-Length");
  if (declared !== null && !(Number(declared) <= max)) return undefined;
  if (request.body === null) return new Uint8Array();
  const chunks: Uint8Array[] = [];
  let length = 0;
  const reader = request.body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > max) {
      await reader.cancel();
      return undefined;
    }
    chunks.push(value);
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

function json(value: unknown, status: number, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { ...headers, "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}
