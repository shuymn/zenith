import { describe, expect, it } from "vitest";
import { classifyKind, type KindClass } from "./kind.ts";

describe("classifyKind", () => {
  it.each<[number, KindClass]>([
    [0, "replaceable"],
    [1, "regular"],
    [2, "regular"],
    [3, "replaceable"],
    [4, "regular"],
    [44, "regular"],
    [45, "unknown"],
    [999, "unknown"],
    [1000, "regular"],
    [9999, "regular"],
    [10000, "replaceable"],
    [19999, "replaceable"],
    [20000, "ephemeral"],
    [29999, "ephemeral"],
    [30000, "addressable"],
    [39999, "addressable"],
    [40000, "unknown"],
    [65535, "unknown"],
  ])("classifies kind %i as %s", (kind, expected) => {
    expect(classifyKind(kind)).toBe(expected);
  });
});
