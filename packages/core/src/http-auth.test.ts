import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import * as nip98 from "nostr-tools/nip98";
import * as nostrTools from "nostr-tools/pure";
import { describe, expect, it } from "vitest";
import type { UnsignedEvent } from "./event.ts";
import {
  verifyHttpAuth,
  type HttpAuthOptions,
  type HttpAuthRejectionCode,
  type HttpAuthVerification,
} from "./http-auth.ts";
import { publicKeyOf, signVerified, testSecretKey } from "./test-support.ts";

const KEY = testSecretKey("http-auth");
const NOW = 1_700_000_000;
const ADMIN_URL = "https://relay.example/admin";
const BODY = utf8ToBytes('{"op":"list"}');

const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** Standard base64 with padding, as RFC 4648 section 4 defines it. */
function base64(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const [a = 0, b = 0, c = 0] = [bytes[i], bytes[i + 1], bytes[i + 2]];
    const n = (a << 16) | (b << 8) | c;
    const chars = [18, 12, 6, 0].map((shift) => BASE64_ALPHABET[(n >> shift) & 63] ?? "");
    const kept = Math.min(bytes.length - i, 3) + 1;
    out += chars.slice(0, kept).join("") + "=".repeat(4 - kept);
  }
  return out;
}

function header(template: Partial<UnsignedEvent> = {}, key = KEY, prefix = ""): string {
  const event = signVerified(
    {
      kind: 27235,
      created_at: NOW,
      tags: [
        ["u", ADMIN_URL],
        ["method", "POST"],
        ["payload", bytesToHex(sha256(BODY))],
      ],
      ...template,
    },
    key,
  );
  return `Nostr ${base64(utf8ToBytes(prefix + JSON.stringify(event)))}`;
}

function verify(authorization: string | null, options: Partial<HttpAuthOptions> = {}): HttpAuthVerification {
  return verifyHttpAuth(authorization, { url: ADMIN_URL, method: "POST", body: BODY, now: NOW, ...options });
}

function codeOf(result: HttpAuthVerification): HttpAuthRejectionCode {
  if (result.ok) throw new Error("expected a rejection");
  return result.code;
}

describe("verifyHttpAuth (NIP-98, OPS-1)", () => {
  it("accepts a matching event and returns its pubkey", () => {
    expect(verify(header())).toEqual({ ok: true, pubkey: publicKeyOf(KEY) });
  });

  it("encodes like the base64 the NIP's example uses", () => {
    expect(base64(utf8ToBytes("a"))).toBe("YQ==");
    expect(base64(utf8ToBytes("ab"))).toBe("YWI=");
    expect(base64(utf8ToBytes("abc"))).toBe("YWJj");
  });

  // A second implementation: nostr-tools' NIP-98 client builds the header, with its own base64 and payload hash.
  it("accepts a header built by nostr-tools' nip98.getToken", async () => {
    const command = { op: "list" };
    const token = await nip98.getToken(
      ADMIN_URL,
      "POST",
      (template) => nostrTools.finalizeEvent(template, KEY),
      true,
      command,
    );
    const now = Math.floor(Date.now() / 1000);
    const body = utf8ToBytes(JSON.stringify(command));
    expect(verifyHttpAuth(token, { url: ADMIN_URL, method: "POST", body, now })).toEqual({
      ok: true,
      pubkey: publicKeyOf(KEY),
    });
    expect(codeOf(verifyHttpAuth(token, { url: ADMIN_URL, method: "POST", body: BODY.slice(1), now }))).toBe(
      "payload-mismatch",
    );
  });

  // NIP-98's example header decodes to its example event, whose id does not match its fields (nostr-tools agrees), so
  // it is refused as an event and not as an encoding.
  it("decodes the example header of NIP-98 and refuses its event, whose id does not match", () => {
    const example =
      "Nostr eyJpZCI6ImZlOTY0ZTc1ODkwMzM2MGYyOGQ4NDI0ZDA5MmRhODQ5NGVkMjA3Y2JhODIzMTEwYmUzYTU3ZGZlNGI1Nzg3MzQiLCJwdWJrZXkiOiI2M2ZlNjMxOGRjNTg1ODNjZmUxNjgxMGY4NmRkMDllMThiZmQ3NmFhYmMyNGEwMDgxY2UyODU2ZjMzMDUwNGVkIiwiY29udGVudCI6IiIsImtpbmQiOjI3MjM1LCJjcmVhdGVkX2F0IjoxNjgyMzI3ODUyLCJ0YWdzIjpbWyJ1IiwiaHR0cHM6Ly9hcGkuc25vcnQuc29jaWFsL2FwaS92MS9uNXNwL2xpc3QiXSxbIm1ldGhvZCIsIkdFVCJdXSwic2lnIjoiNWVkOWQ4ZWM5NThiYzg1NGY5OTdiZGMyNGFjMzM3ZDAwNWFmMzcyMzI0NzQ3ZWZlNGEwMGUyNGY0YzMwNDM3ZmY0ZGQ4MzA4Njg0YmVkNDY3ZDlkNmJlM2U1YTUxN2JiNDNiMTczMmNjN2QzMzk0OWEzYWFmODY3MDVjMjIxODQifQ";
    const options = {
      url: "https://api.snort.social/api/v1/n5sp/list",
      method: "GET",
      body: new Uint8Array(),
      now: 1682327852,
    };
    expect(verifyHttpAuth(example, options)).toEqual({ ok: false, code: "bad-event" });
    const event: nostrTools.Event = JSON.parse(new TextDecoder().decode(decode(example)));
    expect(event).toMatchObject({
      id: "fe964e758903360f28d8424d092da8494ed207cba823110be3a57dfe4b578734",
      kind: 27235,
    });
    expect(nostrTools.verifyEvent(event)).toBe(false);
  });

  // NIP-98: "the `kind 27235` event MUST be `base64` encoded and use the Authorization scheme `Nostr`"
  it.each([
    ["no header", null, "missing"],
    ["an empty header", "", "missing"],
    ["another scheme", header().replace(/^Nostr/, "Bearer"), "bad-scheme"],
    ["the scheme alone", "Nostr", "bad-scheme"],
    ["a value with a space inside", `${header()} x`, "bad-scheme"],
    ["characters outside base64", `${header()}!`, "bad-encoding"],
    ["base64url characters", "Nostr eyJ-_w==", "bad-encoding"],
    ["a length that is not base64", "Nostr eyJpZ", "bad-encoding"],
    ["padding inside the value", "Nostr ey==eyJp", "bad-encoding"],
    ["bytes that are not UTF-8", `Nostr ${base64(new Uint8Array([0xff, 0xfe]))}`, "bad-encoding"],
    // atob skips ASCII whitespace; the exact form is checked before it runs. Two characters keep the length valid.
    ["a line break inside base64", `Nostr ${header().slice(6, 10)}\r\n${header().slice(10)}`, "bad-encoding"],
    ["tabs inside base64", `Nostr ${header().slice(6, 10)}\t\t${header().slice(10)}`, "bad-encoding"],
    ["JSON that is not an event", `Nostr ${base64(utf8ToBytes("[]"))}`, "bad-event"],
  ] as const)("OPS-1: refuses %s", (_name, authorization, code) => {
    expect(codeOf(verify(authorization))).toBe(code);
  });

  it("drops a leading byte order mark of the decoded event, as TextDecoder does by default", () => {
    expect(verify(header({}, KEY, "\uFEFF"))).toEqual({ ok: true, pubkey: publicKeyOf(KEY) });
  });

  it("accepts the scheme in any case and the value without padding", () => {
    expect(verify(header().replace(/^Nostr/, "nostr")).ok).toBe(true);
    // Of three content lengths, at least one gives base64 with padding; it verifies with the padding removed.
    const padded = ["", " ", "  "].map((content) => header({ content })).filter((value) => value.endsWith("="));
    expect(padded.length).toBeGreaterThan(0);
    expect(padded.map((value) => verify(value.replace(/=+$/, "")).ok)).toEqual(padded.map(() => true));
  });

  it("OPS-1: refuses an event whose signature does not verify, with the signature checked by verifyEvent", () => {
    const event: Record<string, unknown> = JSON.parse(new TextDecoder().decode(decode(header())));
    const forged = { ...event, content: "changed" };
    expect(codeOf(verify(`Nostr ${base64(utf8ToBytes(JSON.stringify(forged)))}`))).toBe("bad-event");
  });

  it("refuses an event over the size limit before decoding it", () => {
    const big = header({ content: "x".repeat(20_000) });
    expect(codeOf(verify(big))).toBe("too-large");
    expect(verify(big, { limits: { maxEventBytes: 64 * 1024 } }).ok).toBe(true);
  });

  // NIP-98: "The `kind` MUST be `27235`."
  it.each([1, 22242, 27234, 27236])("OPS-1: refuses kind %i", (kind) => {
    expect(codeOf(verify(header({ kind })))).toBe("wrong-kind");
  });

  // NIP-98: "The `created_at` timestamp MUST be within a reasonable time window (suggestion 60 seconds)."
  it.each([NOW - 60, NOW + 60])("accepts created_at %i, within 60 seconds", (createdAt) => {
    expect(verify(header({ created_at: createdAt })).ok).toBe(true);
  });

  it.each([NOW - 61, NOW + 61, NOW - 600])("OPS-1: refuses created_at %i, an old or future time", (createdAt) => {
    expect(codeOf(verify(header({ created_at: createdAt })))).toBe("stale");
  });

  // NIP-98: "The `u` tag MUST be exactly the same as the absolute request URL (including query parameters)."
  it.each([
    ["another path", "https://relay.example/admin/"],
    ["another host", "https://evil.example/admin"],
    ["another scheme", "http://relay.example/admin"],
    ["a query string", "https://relay.example/admin?x=1"],
    ["another case", "https://Relay.example/admin"],
    ["a relative URL", "/admin"],
  ])("OPS-1: refuses a u tag with %s", (_name, u) => {
    expect(
      codeOf(
        verify(
          header({
            tags: [
              ["u", u],
              ["method", "POST"],
              ["payload", bytesToHex(sha256(BODY))],
            ],
          }),
        ),
      ),
    ).toBe("url-mismatch");
  });

  it("OPS-1: refuses a missing u tag, and checks the first u tag only", () => {
    const payload = ["payload", bytesToHex(sha256(BODY))];
    expect(codeOf(verify(header({ tags: [["method", "POST"], payload] })))).toBe("url-mismatch");
    expect(codeOf(verify(header({ tags: [["u"], ["method", "POST"], payload] })))).toBe("url-mismatch");
    expect(
      codeOf(verify(header({ tags: [["u", "https://evil.example/"], ["u", ADMIN_URL], ["method", "POST"], payload] }))),
    ).toBe("url-mismatch");
  });

  it("matches the u tag against the request URL with its query string", () => {
    const url = `${ADMIN_URL}?a=1&b=2`;
    const tags = [
      ["u", url],
      ["method", "POST"],
      ["payload", bytesToHex(sha256(BODY))],
    ];
    expect(verify(header({ tags }), { url }).ok).toBe(true);
    expect(codeOf(verify(header({ tags }), { url: ADMIN_URL }))).toBe("url-mismatch");
  });

  // NIP-98: "The `method` tag MUST be the same HTTP method used for the requested resource."
  it.each([["GET"], ["post"], ["PUT"], [""]])("OPS-1: refuses a method tag of %j for a POST", (method) => {
    expect(
      codeOf(
        verify(
          header({
            tags: [
              ["u", ADMIN_URL],
              ["method", method],
              ["payload", bytesToHex(sha256(BODY))],
            ],
          }),
        ),
      ),
    ).toBe("method-mismatch");
  });

  it("OPS-1: refuses a missing method tag", () => {
    expect(
      codeOf(
        verify(
          header({
            tags: [
              ["u", ADMIN_URL],
              ["payload", bytesToHex(sha256(BODY))],
            ],
          }),
        ),
      ),
    ).toBe("method-mismatch");
  });

  // NIP-98: "clients SHOULD include a SHA256 hash of the request body in a `payload` tag as hex", and "servers MAY
  // check this". Zenith requires it whenever there is a body, so a signed request cannot carry another body.
  it("OPS-1: refuses a request with a body and no payload tag", () => {
    expect(
      codeOf(
        verify(
          header({
            tags: [
              ["u", ADMIN_URL],
              ["method", "POST"],
            ],
          }),
        ),
      ),
    ).toBe("payload-missing");
  });

  it.each([
    ["another body's hash", bytesToHex(sha256(utf8ToBytes('{"op":"backup"}')))],
    ["the hash in uppercase", bytesToHex(sha256(BODY)).toUpperCase()],
    ["no value", undefined],
  ])("OPS-1: refuses a payload tag with %s", (_name, value) => {
    const payload = value === undefined ? ["payload"] : ["payload", value];
    expect(codeOf(verify(header({ tags: [["u", ADMIN_URL], ["method", "POST"], payload] })))).toBe("payload-mismatch");
  });

  it("accepts a request without a body and without a payload tag, and checks a payload tag when present", () => {
    const empty = new Uint8Array();
    expect(
      verify(
        header({
          tags: [
            ["u", ADMIN_URL],
            ["method", "GET"],
          ],
        }),
        { method: "GET", body: empty },
      ).ok,
    ).toBe(true);
    const wrong = header({
      tags: [
        ["u", ADMIN_URL],
        ["method", "GET"],
        ["payload", bytesToHex(sha256(BODY))],
      ],
    });
    expect(codeOf(verify(wrong, { method: "GET", body: empty }))).toBe("payload-mismatch");
  });

  it("checks in the order NIP-98 lists: kind, created_at, u, then method", () => {
    const tags = [
      ["u", "https://evil.example/"],
      ["method", "GET"],
    ];
    expect(codeOf(verify(header({ kind: 1, created_at: NOW - 600, tags })))).toBe("wrong-kind");
    expect(codeOf(verify(header({ created_at: NOW - 600, tags })))).toBe("stale");
    expect(codeOf(verify(header({ tags })))).toBe("url-mismatch");
  });

  it("returns the signer's key, whoever it is; the caller decides who may act", () => {
    const other = testSecretKey("someone else");
    expect(verify(header({}, other))).toEqual({ ok: true, pubkey: publicKeyOf(other) });
  });
});

/** Decodes the value of a `Nostr` header, for the forgery test. */
function decode(authorization: string): Uint8Array {
  const value = authorization.slice("Nostr ".length).replace(/=+$/, "");
  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const char of value) {
    buffer = (buffer << 6) | BASE64_ALPHABET.indexOf(char);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }
  return new Uint8Array(bytes);
}

declare const TextDecoder: new () => { decode(input: Uint8Array): string };
