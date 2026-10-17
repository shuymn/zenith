import * as fc from "fast-check";
import { describe, expect, it } from "vitest";
import { verifyEvent } from "./event.ts";
import {
  parseClientMessage,
  type ClientMessage,
  type MessageParseResult,
  type MessageRejectionCode,
} from "./message.ts";
import { signVerified, testSecretKey } from "./test-support.ts";

function messageOf(result: MessageParseResult): ClientMessage {
  if (!result.ok) throw new Error(`expected a message: ${result.error.code}`);
  return result.message;
}

function rejectionOf(result: MessageParseResult): MessageRejectionCode {
  if (result.ok) throw new Error("expected a rejection");
  return result.error.code;
}

/** A message of exactly `bytes` UTF-8 bytes, padded inside a tag filter value. */
function frameOfByteLength(type: string, bytes: number): string {
  const empty = `["${type}","x",{"#t":[""]}]`;
  return `["${type}","x",{"#t":["${"a".repeat(bytes - empty.length)}"]}]`;
}

const KEY = testSecretKey("message");

describe("parseClientMessage", () => {
  describe("RES-1: the message size is checked before parsing", () => {
    it("accepts a message of exactly 512 KiB and refuses 512 KiB + 1 byte", () => {
      expect(messageOf(parseClientMessage(frameOfByteLength("REQ", 512 * 1024))).type).toBe("REQ");
      expect(rejectionOf(parseClientMessage(frameOfByteLength("REQ", 512 * 1024 + 1)))).toBe("too-large");
    });

    it("counts UTF-8 bytes rather than UTF-16 code units", () => {
      // 3 bytes per character, so 200_000 characters are 600_000 bytes, over 512 KiB.
      const raw = `["REQ","x",{"#t":["${"あ".repeat(200_000)}"]}]`;
      expect(raw.length).toBeLessThan(512 * 1024);
      expect(rejectionOf(parseClientMessage(raw))).toBe("too-large");
    });

    it("refuses oversized input that is not even JSON as too large, not as malformed", () => {
      expect(rejectionOf(parseClientMessage("[".repeat(512 * 1024 + 1)))).toBe("too-large");
    });
  });

  describe("shape", () => {
    it.each([
      ["not JSON", "[", "malformed-json"],
      ["a JSON object", '{"type":"EVENT"}', "not-message"],
      ["an empty array", "[]", "not-message"],
      ["a type that is not a string", "[1, {}]", "not-message"],
      ["an unknown type", '["COUNT","x",{}]', "unknown-type"],
      ["a lowercase type", '["event",{}]', "unknown-type"],
      ["EVENT without an event", '["EVENT"]', "bad-shape"],
      ["EVENT with two events", '["EVENT",{},{}]', "bad-shape"],
      ["AUTH without an event", '["AUTH"]', "bad-shape"],
      ["REQ without a subscription id", '["REQ"]', "bad-shape"],
      ["REQ with an empty subscription id", '["REQ","",{}]', "bad-subscription-id"],
      ["REQ with a numeric subscription id", '["REQ",1,{}]', "bad-subscription-id"],
      ["REQ with a 65-character subscription id", `["REQ","${"s".repeat(65)}",{}]`, "bad-subscription-id"],
      ["CLOSE without a subscription id", '["CLOSE"]', "bad-shape"],
      ["CLOSE with extra elements", '["CLOSE","x","y"]', "bad-shape"],
      ["CLOSE with a bad subscription id", '["CLOSE",""]', "bad-subscription-id"],
    ] as const)("refuses %s", (_name, raw, code) => {
      expect(rejectionOf(parseClientMessage(raw))).toBe(code);
    });

    it("gives the subscription id and the filter values of a REQ", () => {
      expect(messageOf(parseClientMessage('["REQ","sub",{"kinds":[1]},{"limit":2}]'))).toEqual({
        type: "REQ",
        subscriptionId: "sub",
        filters: [{ kinds: [1] }, { limit: 2 }],
      });
      // parseFilters refuses a REQ without filters; the message itself is well formed.
      expect(messageOf(parseClientMessage('["REQ","sub"]'))).toEqual({
        type: "REQ",
        subscriptionId: "sub",
        filters: [],
      });
    });

    it("gives the subscription id of a CLOSE", () => {
      expect(messageOf(parseClientMessage('["CLOSE","sub"]'))).toEqual({ type: "CLOSE", subscriptionId: "sub" });
    });
  });

  describe("EV-1, RES-1: EVENT and AUTH give the event as received text, for verifyEvent", () => {
    it("gives exactly the text of the event element, whitespace inside it included", () => {
      const eventText = '{ "id" : "a,]}" ,\n "tags":[["x","[\\"]"]] }';
      expect(messageOf(parseClientMessage(` [ "EVENT" ,\n ${eventText} \t] `))).toEqual({ type: "EVENT", eventText });
      expect(messageOf(parseClientMessage(`["AUTH",${eventText}]`))).toEqual({ type: "AUTH", eventText });
    });

    it("gives text that verifyEvent accepts for a signed event", () => {
      const event = signVerified({ content: 'a "quoted" ] , } text' }, KEY);
      const message = messageOf(parseClientMessage(`["EVENT",${JSON.stringify(event)}]`));
      if (message.type !== "EVENT") throw new Error("expected EVENT");
      const verified = verifyEvent(message.eventText, { now: event.created_at });
      expect(verified.ok && verified.event).toEqual(event);
    });

    it("gives a non-object event as text too, so that verifyEvent answers it", () => {
      expect(messageOf(parseClientMessage('["EVENT","not an event"]'))).toEqual({
        type: "EVENT",
        eventText: '"not an event"',
      });
    });

    it("lets verifyEvent refuse an event over 256 KiB inside a message under 512 KiB", () => {
      const event = signVerified({ content: "a".repeat(300 * 1024) }, KEY);
      const message = messageOf(parseClientMessage(`["EVENT",${JSON.stringify(event)}]`));
      if (message.type !== "EVENT") throw new Error("expected EVENT");
      const verified = verifyEvent(message.eventText, { now: event.created_at });
      expect(verified.ok).toBe(false);
      expect(!verified.ok && verified.error.code).toBe("too-large");
    });

    it("gives exactly the element's text for any JSON value, however it is formatted", () => {
      const whitespace = fc.constantFrom("", " ", "\n", "\t", "\r\n ");
      fc.assert(
        fc.property(fc.jsonValue(), fc.constantFrom(0, 2), whitespace, (value, indent, space) => {
          const eventText = JSON.stringify(value, null, indent);
          const message = messageOf(parseClientMessage(`[${space}"EVENT"${space},${space}${eventText}${space}]`));
          expect(message).toEqual({ type: "EVENT", eventText });
        }),
      );
    });
  });
});
