/**
 * The relay's only path to `console` (DATA-1). Workers Logs keep console output for 7 days, so a log line is an event
 * name and fields whose values come from closed sets: never a received message, an event, its content, an AUTH event
 * or an error's message. The source analysis test refuses `console` in every other file.
 */
import type { ClientMessageType } from "@zenith/core";
import type { RelayConfigError } from "./config.ts";

export const LOG_EVENTS = [
  "zenith.config.invalid",
  "zenith.store.unavailable",
  "zenith.message.failed",
  "zenith.delivery.failed",
  "zenith.alarm.failed",
] as const;
export type LogEvent = (typeof LOG_EVENTS)[number];

/** Error classes logged by name. Any other value, a custom error class included, is logged as `other`. */
export const ERROR_NAMES = ["Error", "TypeError", "RangeError", "SyntaxError", "other"] as const;
export type ErrorName = (typeof ERROR_NAMES)[number];

/** Every field a log line can carry, each typed by a closed set or a number. */
export type LogFields = {
  readonly error?: ErrorName;
  readonly message?: ClientMessageType | "binary" | "unparsed";
  readonly reason?: RelayConfigError | "owner-revoked" | "owner-retired";
  readonly connections?: number;
};

export function logEvent(event: LogEvent, fields: LogFields = {}): void {
  console.error(JSON.stringify({ event, ...fields }));
}

/** The class of a thrown value, without its message. */
export function errorName(error: unknown): ErrorName {
  if (!(error instanceof Error)) return "other";
  const name = error.constructor.name;
  return ERROR_NAMES.find((known) => known === name) ?? "other";
}
