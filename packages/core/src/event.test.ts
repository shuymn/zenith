import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { finalizeEvent, getEventHash } from "nostr-tools/pure";
import { describe, expect, it } from "vitest";
import {
  computeEventId,
  type EventRejection,
  type EventRejectionCode,
  type EventVerification,
  formatOkMessage,
  serializeEvent,
  verifyEvent,
  verifyEventObject,
  type NostrEvent,
  type UnsignedEvent,
} from "./event.ts";

// Test-only keys derived from fixed labels. They are not used anywhere else.
const SECRET_KEY = sha256(utf8ToBytes("zenith test key A"));
const OTHER_SECRET_KEY = sha256(utf8ToBytes("zenith test key B"));
const PUBKEY = bytesToHex(schnorr.getPublicKey(SECRET_KEY));
const OTHER_PUBKEY = bytesToHex(schnorr.getPublicKey(OTHER_SECRET_KEY));
const AUX_RAND = new Uint8Array(32);
const NOW = 1_700_000_000;

function sign(template: Partial<UnsignedEvent>, secretKey: Uint8Array = SECRET_KEY): NostrEvent {
  const unsigned: UnsignedEvent = {
    pubkey: bytesToHex(schnorr.getPublicKey(secretKey)),
    created_at: NOW,
    kind: 1,
    tags: [],
    content: "",
    ...template,
  };
  const id = computeEventId(unsigned);
  const sig = bytesToHex(schnorr.sign(hexToBytes(id), secretKey, AUX_RAND));
  return { ...unsigned, id, sig };
}

function verifyRaw(raw: string, options: Parameters<typeof verifyEvent>[1] = {}) {
  return verifyEvent(raw, { now: NOW, ...options });
}

function verifyObject(value: unknown, options: Parameters<typeof verifyEventObject>[1] = {}) {
  return verifyEventObject(value, { now: NOW, ...options });
}

function errorOf(result: EventVerification): EventRejection {
  if (result.ok) throw new Error("expected the event to be rejected");
  return result.error;
}

function eventOf(result: EventVerification): NostrEvent {
  if (!result.ok) throw new Error(`expected the event to be accepted: ${result.error.code}`);
  return result.event;
}

function rejectedAs(code: EventRejectionCode) {
  return { prefix: "invalid", code };
}

function eventOfByteLength(bytes: number): string {
  const base = JSON.stringify(sign({ content: "" }));
  const raw = JSON.stringify(sign({ content: "a".repeat(bytes - utf8ToBytes(base).length) }));
  expect(utf8ToBytes(raw).length).toBe(bytes);
  return raw;
}

// Array.prototype.every() skips holes, so sparse arrays must be checked element by element.
function sparse(length: number, ...items: [number, string][]): unknown[] {
  const array: unknown[] = [];
  array.length = length;
  for (const [index, item] of items) array[index] = item;
  return array;
}

function sha256Hex(text: string): string {
  return bytesToHex(sha256(utf8ToBytes(text)));
}

// EV-2: the id follows NIP-01's serialization.
describe("serializeEvent / computeEventId", () => {
  // NIP-01: "The following characters in the content field must be escaped as shown,
  // and all other characters must be included verbatim".
  // The expected strings below are written by hand from that rule, not produced by JSON.stringify.
  it.each<[string, string, string]>([
    ["line break 0x0A as \\n", "a\nb", String.raw`"a\nb"`],
    ['double quote 0x22 as \\"', 'a"b', String.raw`"a\"b"`],
    ["backslash 0x5C as \\\\", "a\\b", String.raw`"a\\b"`],
    ["carriage return 0x0D as \\r", "a\rb", String.raw`"a\rb"`],
    ["tab 0x09 as \\t", "a\tb", String.raw`"a\tb"`],
    ["backspace 0x08 as \\b", "a\u0008b", String.raw`"a\bb"`],
    ["form feed 0x0C as \\f", "a\u000Cb", String.raw`"a\fb"`],
    ["U+0000 verbatim", "a\u0000b", '"a\u0000b"'],
    ["U+0001 verbatim", "a\u0001b", '"a\u0001b"'],
    ["U+000B verbatim", "a\u000Bb", '"a\u000Bb"'],
    ["U+001F verbatim", "a\u001Fb", '"a\u001Fb"'],
    ["U+007F verbatim", "a\u007Fb", '"a\u007Fb"'],
    ["U+2028 / U+2029 verbatim", "a b c", '"a b c"'],
    ["emoji verbatim", "a\u{1F600}b", '"a\u{1F600}b"'],
    ["non-ASCII verbatim", "日本語 é", '"日本語 é"'],
    ["slash verbatim", "a/b", '"a/b"'],
    ["all seven escapes together", '\n"\\\r\t\u0008\u000C', String.raw`"\n\"\\\r\t\b\f"`],
  ])("content: %s", (_name, content, expectedContentJson) => {
    const unsigned: UnsignedEvent = { pubkey: PUBKEY, created_at: NOW, kind: 1, tags: [], content };
    const expected = `[0,"${PUBKEY}",${NOW},1,[],${expectedContentJson}]`;
    expect(serializeEvent(unsigned)).toBe(expected);
    expect(computeEventId(unsigned)).toBe(sha256Hex(expected));
  });

  it("applies the same escaping rule to tag strings", () => {
    const unsigned: UnsignedEvent = {
      pubkey: PUBKEY,
      created_at: NOW,
      kind: 1,
      tags: [["t", 'a\n"\\\u0001/'], ["e"]],
      content: "",
    };
    const expected = `[0,"${PUBKEY}",${NOW},1,[["t","a\\n\\"\\\\\u0001/"],["e"]],""]`;
    expect(serializeEvent(unsigned)).toBe(expected);
    expect(computeEventId(unsigned)).toBe(sha256Hex(expected));
  });

  it("matches nostr-tools for ordinary strings", () => {
    const unsigned: UnsignedEvent = {
      pubkey: PUBKEY,
      created_at: NOW,
      kind: 30023,
      tags: [
        ["d", "article"],
        ["p", OTHER_PUBKEY, "wss://relay.example.com"],
      ],
      content: 'Hello "nostr"\n\tこんにちは \u{1F600} a\\b',
    };
    expect(computeEventId(unsigned)).toBe(getEventHash(unsigned));
  });

  it("refuses to hash a lone surrogate, which has no UTF-8 encoding", () => {
    const unsigned: UnsignedEvent = { pubkey: PUBKEY, created_at: NOW, kind: 1, tags: [], content: "\uD800" };
    expect(() => computeEventId(unsigned)).toThrow(RangeError);
  });
});

describe("verifyEvent", () => {
  it("accepts a correctly signed event and returns its fields", () => {
    const event = sign({ content: "hello", tags: [["t", "zenith"]] });
    const result = verifyRaw(JSON.stringify(event));
    expect(result).toEqual({ ok: true, event });
  });

  it("accepts content with control characters signed under the NIP-01 rule", () => {
    const event = sign({ content: "\u0000\u0001\u001F\u007F " });
    expect(verifyRaw(JSON.stringify(event)).ok).toBe(true);
  });

  // EV-2: the JSON.stringify form is also accepted, and only when a string holds such a character.
  describe("control characters outside the seven NIP-01 escapes", () => {
    // NIP-01 includes them verbatim, while JSON.stringify-based clients escape them as \u00XX.
    const template = { content: "a\u0001b\u001Fc\n", tags: [["t", "\u0000"]] };
    const jsonStringifyForm = `[0,"${PUBKEY}",${NOW},1,[["t","\\u0000"]],"a\\u0001b\\u001fc\\n"]`;

    function signWithId(id: string): NostrEvent {
      const sig = bytesToHex(schnorr.sign(hexToBytes(id), SECRET_KEY, AUX_RAND));
      return { pubkey: PUBKEY, created_at: NOW, kind: 1, ...template, id, sig };
    }

    it("accepts an id computed with the NIP-01 serialization", () => {
      const event = sign(template);
      expect(event.id).not.toBe(sha256Hex(jsonStringifyForm));
      expect(verifyRaw(JSON.stringify(event)).ok).toBe(true);
    });

    it("accepts an id computed with the JSON.stringify serialization", () => {
      expect(verifyRaw(JSON.stringify(signWithId(sha256Hex(jsonStringifyForm)))).ok).toBe(true);
    });

    it("rejects an id matching neither serialization", () => {
      const otherForm = jsonStringifyForm.replace("\\u001f", "\\u001F");
      expect(errorOf(verifyRaw(JSON.stringify(signWithId(sha256Hex(otherForm)))))).toMatchObject(
        rejectedAs("id-mismatch"),
      );
    });

    it("accepts an event created by nostr-tools finalizeEvent", () => {
      const event = finalizeEvent({ created_at: NOW, kind: 1, ...template }, SECRET_KEY);
      expect(verifyRaw(JSON.stringify(event)).ok).toBe(true);
    });

    it("keeps computeEventId on the NIP-01 serialization", () => {
      const unsigned: UnsignedEvent = { pubkey: PUBKEY, created_at: NOW, kind: 1, ...template };
      expect(computeEventId(unsigned)).not.toBe(getEventHash(unsigned));
    });
  });

  it("decodes an escaped surrogate pair to the same id as the raw character", () => {
    const event = sign({ content: "\u{1F600}" });
    const raw = JSON.stringify(event).replace("\u{1F600}", String.raw`\ud83d\ude00`);
    expect(raw).toContain(String.raw`\ud83d\ude00`);
    expect(verifyRaw(raw).ok).toBe(true);
  });

  // EV-1: the id and signature are recomputed on every call.
  describe("tampering", () => {
    const event = sign({ content: "original" });

    it("rejects an id with one character changed", () => {
      const id = (event.id[0] === "0" ? "1" : "0") + event.id.slice(1);
      expect(errorOf(verifyRaw(JSON.stringify({ ...event, id })))).toMatchObject(rejectedAs("id-mismatch"));
    });

    it("rejects modified content", () => {
      expect(errorOf(verifyRaw(JSON.stringify({ ...event, content: "modified" })))).toMatchObject(
        rejectedAs("id-mismatch"),
      );
    });

    it("rejects a modified signature", () => {
      const sig = event.sig.slice(0, -1) + (event.sig.endsWith("0") ? "1" : "0");
      expect(errorOf(verifyRaw(JSON.stringify({ ...event, sig })))).toMatchObject(rejectedAs("bad-signature"));
    });

    it("rejects a different pubkey", () => {
      expect(errorOf(verifyRaw(JSON.stringify({ ...event, pubkey: OTHER_PUBKEY })))).toMatchObject(
        rejectedAs("id-mismatch"),
      );
    });

    it("rejects a different pubkey even when the id is recomputed for it", () => {
      const forged = { ...event, pubkey: OTHER_PUBKEY };
      forged.id = computeEventId(forged);
      expect(errorOf(verifyRaw(JSON.stringify(forged)))).toMatchObject(rejectedAs("bad-signature"));
    });

    it("rejects a signature made by another key over the same id", () => {
      const sig = bytesToHex(schnorr.sign(hexToBytes(event.id), OTHER_SECRET_KEY, AUX_RAND));
      expect(errorOf(verifyRaw(JSON.stringify({ ...event, sig })))).toMatchObject(rejectedAs("bad-signature"));
    });

    it("rejects an event object mutated after a successful verification", () => {
      const verified = eventOf(verifyObject(structuredClone(event)));
      verified.content = "mutated";
      expect(errorOf(verifyObject(verified))).toMatchObject(rejectedAs("id-mismatch"));
      expect(errorOf(verifyRaw(JSON.stringify(verified)))).toMatchObject(rejectedAs("id-mismatch"));
    });

    it("rejects an input object mutated after a successful verification", () => {
      const input: Record<string, unknown> = structuredClone(event);
      expect(verifyObject(input).ok).toBe(true);
      input["kind"] = 2;
      expect(errorOf(verifyObject(input))).toMatchObject(rejectedAs("id-mismatch"));
    });
  });

  // EV-3: the structure is checked before any use; EV-2: a lone surrogate escape is rejected.
  describe("structure", () => {
    const event = sign({ content: "structure", tags: [["t", "a"]] });

    it.each<[string, Record<string, unknown>, EventRejectionCode]>([
      ["uppercase id", { id: event.id.toUpperCase() }, "bad-id"],
      ["short id", { id: event.id.slice(1) }, "bad-id"],
      ["uppercase pubkey", { pubkey: event.pubkey.toUpperCase() }, "bad-pubkey"],
      ["long pubkey", { pubkey: `${event.pubkey}00` }, "bad-pubkey"],
      ["uppercase sig", { sig: event.sig.toUpperCase() }, "bad-sig"],
      ["short sig", { sig: event.sig.slice(2) }, "bad-sig"],
      ["kind 65536", { kind: 65536 }, "bad-kind"],
      ["kind -1", { kind: -1 }, "bad-kind"],
      ["kind 1.5", { kind: 1.5 }, "bad-kind"],
      ["kind as string", { kind: "1" }, "bad-kind"],
      ["created_at 1.5", { created_at: NOW + 0.5 }, "bad-created-at"],
      ["created_at as string", { created_at: String(NOW) }, "bad-created-at"],
      ["negative created_at", { created_at: -1 }, "bad-created-at"],
      ["tags not an array", { tags: {} }, "bad-tags"],
      ["tag not an array", { tags: ["t"] }, "bad-tags"],
      ["null in a tag", { tags: [["t", null]] }, "bad-tags"],
      // NIP-01: "Each tag is an array of one or more strings".
      ["empty tag", { tags: [[]] }, "bad-tags"],
      ["number in a tag", { tags: [["t", 1]] }, "bad-tags"],
      ["content not a string", { content: 1 }, "bad-content"],
      ["content null", { content: null }, "bad-content"],
    ])("rejects %s", (_name, override, code) => {
      expect(errorOf(verifyRaw(JSON.stringify({ ...event, ...override })))).toMatchObject(rejectedAs(code));
    });

    it.each(["id", "pubkey", "created_at", "kind", "tags", "content", "sig"])("rejects a missing %s", (field) => {
      const copy: Record<string, unknown> = { ...event };
      delete copy[field];
      expect(verifyRaw(JSON.stringify(copy)).ok).toBe(false);
    });

    it.each([0, 65535])("accepts kind %i", (kind) => {
      expect(verifyRaw(JSON.stringify(sign({ kind }))).ok).toBe(true);
    });

    it.each(["[]", "null", '"event"', "1"])("rejects a non-object JSON value %s", (raw) => {
      expect(errorOf(verifyRaw(raw))).toMatchObject(rejectedAs("not-object"));
    });

    it.each([
      ["a sparse tags array", sparse(1)],
      ["a sparse tag", [sparse(1)]],
      ["a sparse tag after a string", [sparse(3, [0, "t"], [2, "x"])]],
    ])("rejects %s without throwing", (_name, tags) => {
      expect(errorOf(verifyObject({ ...event, tags }))).toMatchObject(rejectedAs("bad-tags"));
    });

    it("rejects malformed JSON", () => {
      expect(errorOf(verifyRaw("{"))).toMatchObject(rejectedAs("malformed-json"));
    });

    it("accepts unknown fields, ignores them for the id and drops them from the result", () => {
      const result = verifyRaw(JSON.stringify({ ...event, extra: { nested: true } }));
      expect(result).toEqual({ ok: true, event });
    });

    // The raw JSON carries the literal escape sequence, as a client would send it.
    const placeholder = "\u{E000}";
    it.each([
      ["content (lone high surrogate)", { content: placeholder }, String.raw`a\ud800b`],
      ["content (lone low surrogate)", { content: placeholder }, String.raw`\udc00`],
      ["content (reversed pair)", { content: placeholder }, String.raw`\ude00\ud83d`],
      ["a tag", { tags: [["t", placeholder]] }, String.raw`\ud800`],
    ])("rejects a lone surrogate escape in %s", (_name, override, escape) => {
      const raw = JSON.stringify({ ...event, ...override }).replace(placeholder, escape);
      expect(errorOf(verifyRaw(raw))).toMatchObject(rejectedAs("invalid-unicode"));
    });

    it("reports the event id when the id field is well-formed", () => {
      expect(errorOf(verifyRaw(JSON.stringify({ ...event, content: "modified" }))).eventId).toBe(event.id);
    });

    it("omits the event id when the id field is malformed", () => {
      expect(errorOf(verifyRaw(JSON.stringify({ ...event, id: "x" }))).eventId).toBeUndefined();
    });
  });

  // EV-4: created_at at most 900 seconds in the future.
  describe("created_at window", () => {
    it("accepts created_at at now + 900 seconds", () => {
      expect(verifyRaw(JSON.stringify(sign({ created_at: NOW + 900 }))).ok).toBe(true);
    });

    it("rejects created_at at now + 901 seconds", () => {
      expect(errorOf(verifyRaw(JSON.stringify(sign({ created_at: NOW + 901 }))))).toMatchObject(
        rejectedAs("created-at-too-far-in-future"),
      );
    });

    it("does not limit how far in the past created_at is", () => {
      expect(verifyRaw(JSON.stringify(sign({ created_at: 0 }))).ok).toBe(true);
    });

    it("uses the current clock when now is not given", () => {
      const event = sign({ created_at: Math.floor(Date.now() / 1000) + 3600 });
      expect(errorOf(verifyEvent(JSON.stringify(event)))).toMatchObject(rejectedAs("created-at-too-far-in-future"));
    });

    it("accepts an overridden future limit", () => {
      const raw = JSON.stringify(sign({ created_at: NOW + 901 }));
      expect(verifyRaw(raw, { limits: { maxFutureSeconds: 901 } }).ok).toBe(true);
    });
  });

  // RES-1: input is bounded before it is used.
  describe("size limits", () => {
    it("accepts an event of exactly 256 KiB", () => {
      expect(verifyRaw(eventOfByteLength(256 * 1024)).ok).toBe(true);
    });

    it("rejects an event of 256 KiB + 1 byte", () => {
      expect(errorOf(verifyRaw(eventOfByteLength(256 * 1024 + 1)))).toMatchObject(rejectedAs("too-large"));
    });

    it("counts UTF-8 bytes rather than UTF-16 code units", () => {
      const raw = JSON.stringify(sign({ content: "あ".repeat(100) }));
      const bytes = utf8ToBytes(raw).length;
      expect(verifyRaw(raw, { limits: { maxEventBytes: bytes } }).ok).toBe(true);
      expect(errorOf(verifyRaw(raw, { limits: { maxEventBytes: raw.length + 1 } }))).toMatchObject(
        rejectedAs("too-large"),
      );
    });

    it("accepts 2000 tags and rejects 2001", () => {
      const tags = Array.from({ length: 2000 }, (_, i) => ["t", String(i)]);
      expect(verifyRaw(JSON.stringify(sign({ tags }))).ok).toBe(true);
      expect(errorOf(verifyRaw(JSON.stringify(sign({ tags: [...tags, ["t", "x"]] }))))).toMatchObject(
        rejectedAs("too-many-tags"),
      );
    });

    it("accepts a 1 KiB tag value and rejects 1 KiB + 1 byte", () => {
      expect(verifyRaw(JSON.stringify(sign({ tags: [["t", "a".repeat(1024)]] }))).ok).toBe(true);
      expect(errorOf(verifyRaw(JSON.stringify(sign({ tags: [["t", "a".repeat(1025)]] }))))).toMatchObject(
        rejectedAs("tag-too-large"),
      );
    });

    it("measures tag values in UTF-8 bytes, including the tag name and later elements", () => {
      // 341 * 3 + 1 = 1024 bytes, 342 * 3 = 1026 bytes.
      expect(verifyRaw(JSON.stringify(sign({ tags: [["t", `${"あ".repeat(341)}a`]] }))).ok).toBe(true);
      expect(errorOf(verifyRaw(JSON.stringify(sign({ tags: [["t", "あ".repeat(342)]] }))))).toMatchObject(
        rejectedAs("tag-too-large"),
      );
      expect(errorOf(verifyRaw(JSON.stringify(sign({ tags: [["a".repeat(1025)]] }))))).toMatchObject(
        rejectedAs("tag-too-large"),
      );
      expect(errorOf(verifyRaw(JSON.stringify(sign({ tags: [["r", "x", "a".repeat(1025)]] }))))).toMatchObject(
        rejectedAs("tag-too-large"),
      );
    });

    it("applies overridden limits", () => {
      const raw = JSON.stringify(
        sign({
          tags: [
            ["t", "abc"],
            ["t", "d"],
          ],
        }),
      );
      expect(errorOf(verifyRaw(raw, { limits: { maxTags: 1 } }))).toMatchObject(rejectedAs("too-many-tags"));
      expect(errorOf(verifyRaw(raw, { limits: { maxTagValueBytes: 2 } }))).toMatchObject(rejectedAs("tag-too-large"));
    });
  });
});

describe("formatOkMessage", () => {
  it("formats a rejection as a NIP-01 machine-readable prefix and message", () => {
    expect(formatOkMessage(errorOf(verifyRaw("{")))).toMatch(/^invalid: \S/);
  });
});
