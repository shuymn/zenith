import { describe, expect, it } from "vitest";
import { decodeBase64, decodeUtf8Strict, isHex32, isRecord, parseJsonText } from "./encoding.ts";

describe("isHex32", () => {
  it("accepts exactly 64 lowercase hex characters", () => {
    expect(isHex32("0123456789abcdef".repeat(4))).toBe(true);
  });

  // NIP-01: "exact 64-character lowercase hex values".
  it.each([
    ["uppercase", "0123456789ABCDEF".repeat(4)],
    ["63 characters", "a".repeat(63)],
    ["65 characters", "a".repeat(65)],
    ["a trailing newline", `${"a".repeat(64)}\n`],
    ["a non-hex letter", `${"a".repeat(63)}g`],
    ["an npub-like value", "npub1".padEnd(64, "q")],
  ])("refuses %s", (_name, value) => {
    expect(isHex32(value)).toBe(false);
  });

  it("refuses values that are not strings", () => {
    for (const value of [undefined, null, 1, ["a".repeat(64)], { toString: () => "a".repeat(64) }]) {
      expect(isHex32(value)).toBe(false);
    }
  });
});

describe("isRecord", () => {
  it("is true for objects only, not null or arrays", () => {
    expect(isRecord({})).toBe(true);
    expect(isRecord(Object.create(null))).toBe(true);
    for (const value of [null, [], "x", 1, undefined]) expect(isRecord(value)).toBe(false);
  });
});

describe("decodeUtf8Strict", () => {
  it("decodes UTF-8", () => {
    expect(decodeUtf8Strict(new Uint8Array([0x68, 0xc3, 0xa9]))).toBe("hé");
  });

  it("refuses bytes that are not UTF-8 instead of replacing them", () => {
    expect(decodeUtf8Strict(new Uint8Array([0x68, 0xff]))).toBeUndefined();
    // An encoded lone surrogate (U+D800).
    expect(decodeUtf8Strict(new Uint8Array([0xed, 0xa0, 0x80]))).toBeUndefined();
  });

  it("keeps a leading byte order mark unless asked to strip it", () => {
    const bytes = new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d]);
    expect(decodeUtf8Strict(bytes)).toBe("﻿{}");
    expect(decodeUtf8Strict(bytes, { stripBom: true })).toBe("{}");
  });
});

describe("parseJsonText", () => {
  it("returns the value or a failure, never throws", () => {
    expect(parseJsonText('{"a":[1]}')).toEqual({ ok: true, value: { a: [1] } });
    expect(parseJsonText("null")).toEqual({ ok: true, value: null });
    for (const text of ["", "{", "﻿{}", "undefined"]) expect(parseJsonText(text)).toEqual({ ok: false });
  });
});

describe("decodeBase64", () => {
  it("decodes to bytes, padded or not", () => {
    expect(decodeBase64("aGk=")).toEqual(new Uint8Array([0x68, 0x69]));
    expect(decodeBase64("aGk")).toEqual(new Uint8Array([0x68, 0x69]));
    expect(decodeBase64("/w==")).toEqual(new Uint8Array([0xff]));
  });

  it("gives undefined for what atob refuses", () => {
    expect(decodeBase64("a")).toBeUndefined();
    expect(decodeBase64("a*b=")).toBeUndefined();
  });
});
