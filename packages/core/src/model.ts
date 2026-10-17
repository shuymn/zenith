/**
 * Reference model of the storage semantics: the oracle that stage 2's storage is compared with.
 * It favors being obviously correct over being fast, and depends on nothing outside packages/core.
 * Its input is events that already passed write authorization.
 */
import { canonicalEventJson } from "./canonical.ts";
import type { VerifiedEvent } from "./event.ts";
import { matchesFilter, resolveLimit, type Filter } from "./filter.ts";
import { classifyKind, type KindClass } from "./kind.ts";
import type { FilterLimits } from "./limits.ts";

/** Stored events by id, replaced versions included. Deleted events are removed. */
export type ModelState = { readonly events: ReadonlyMap<string, VerifiedEvent> };

export const EMPTY_STATE: ModelState = Object.freeze({ events: new Map<string, VerifiedEvent>() });

export const APPLY_OUTCOMES = [
  "stored",
  "stored-as-history",
  "duplicate",
  "rejected-deleted",
  "rejected-expired",
  "not-stored-ephemeral",
] as const;
export type ApplyOutcome = (typeof APPLY_OUTCOMES)[number];

export type ApplyResult = { [K in ApplyOutcome]: { outcome: K; state: ModelState } }[ApplyOutcome];

/** How an `OK` message answers each outcome. NIP-01 prefixes. */
const OK_RESPONSES: Record<ApplyOutcome, { accepted: boolean; message: string }> = {
  stored: { accepted: true, message: "" },
  // The older version is kept as history (ST-4); the write itself succeeded.
  "stored-as-history": { accepted: true, message: "" },
  // NIP-01: `["OK", "b1a649ebe8...", true, "duplicate: already have this event"]`
  duplicate: { accepted: true, message: "duplicate: already have this event" },
  "rejected-deleted": { accepted: false, message: "blocked: this event was deleted by its author" },
  // EV-6: an event already expired on receipt answers `invalid:`.
  "rejected-expired": { accepted: false, message: "invalid: event has expired" },
  // Accepted for delivery, never stored (WR-5).
  "not-stored-ephemeral": { accepted: true, message: "" },
};

/** How each kind class is stored. `unknown` is stored like `regular`. */
const STORAGE: Record<KindClass, "each" | "versioned" | "never"> = {
  regular: "each",
  unknown: "each",
  replaceable: "versioned",
  addressable: "versioned",
  ephemeral: "never",
};

const DELETION_KIND = 5;

export function toOkResponse(outcome: ApplyOutcome): { accepted: boolean; message: string } {
  return OK_RESPONSES[outcome];
}

/** Applies one write at time `now` (unix seconds) and returns the new state. The given state is not changed. */
export function apply(state: ModelState, event: VerifiedEvent, now: number): ApplyResult {
  const storage = STORAGE[classifyKind(event.kind)];
  // NIP-40: "An expiration timestamp does not affect storage of ephemeral events."
  if (storage === "never") return { outcome: "not-stored-ephemeral", state };
  // EV-6. NIP-40: "Relays SHOULD drop any events that are published to them if they are expired."
  if (isExpired(event, now)) return { outcome: "rejected-expired", state };
  if (state.events.has(event.id)) return { outcome: "duplicate", state };
  // ST-2: stored deletion requests are checked on every write, so a deletion that arrived first still holds.
  for (const stored of state.events.values()) {
    if (deletes(stored, event)) return { outcome: "rejected-deleted", state };
  }

  const events = new Map(state.events);
  events.set(event.id, event);
  if (event.kind === DELETION_KIND) {
    for (const stored of state.events.values()) {
      if (deletes(event, stored)) events.delete(stored.id);
    }
  }
  const replacedBy = storage === "versioned" ? newerVersionOf(event, state.events.values()) : undefined;
  return { outcome: replacedBy === undefined ? "stored" : "stored-as-history", state: { events } };
}

/**
 * The stored events a REQ with these filters returns at time `now`: per filter, the matching events
 * newest first (ties by lower id) up to the filter's limit; then the union, without duplicates, in the same order.
 * A filter with `ids` also returns replaced versions (ST-4). Expired events are never returned (ST-3).
 */
export function query(
  state: ModelState,
  filters: readonly Filter[],
  now: number,
  limits: Partial<FilterLimits> = {},
): VerifiedEvent[] {
  const all = [...state.events.values()];
  const live = all.filter((event) => !isExpired(event, now));
  const current = live.filter(
    (event) => STORAGE[classifyKind(event.kind)] !== "versioned" || newerVersionOf(event, all) === undefined,
  );
  const result = new Map<string, VerifiedEvent>();
  for (const filter of filters) {
    const candidates = filter.ids === undefined ? current : live;
    const matched = candidates.filter((event) => matchesFilter(event, filter)).toSorted(compareForQuery);
    for (const event of matched.slice(0, resolveLimit(filter, limits))) result.set(event.id, event);
  }
  return [...result.values()].toSorted(compareForQuery);
}

/** The canonical JSON (ST-7) of every stored event, replaced versions included, sorted by id. */
export function canonicalEvents(state: ModelState): string[] {
  return [...state.events.values()].toSorted((a, b) => compareStrings(a.id, b.id)).map(canonicalEventJson);
}

// NIP-01: "Newer events should appear first, and in the case of ties the event with the lowest id
// (first in lexical order) should be first."
function compareForQuery(a: VerifiedEvent, b: VerifiedEvent): number {
  return b.created_at - a.created_at || compareStrings(a.id, b.id);
}

function compareStrings(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

/** A stored version of the same address that wins over `event`, if any (ST-1). */
function newerVersionOf(event: VerifiedEvent, events: Iterable<VerifiedEvent>): VerifiedEvent | undefined {
  const address = addressOf(event);
  for (const other of events) {
    if (other.id !== event.id && addressOf(other) === address && wins(other, event)) return other;
  }
  return undefined;
}

// NIP-01: "In case of replaceable events with the same timestamp, the event with the lowest id
// (first in lexical order) should be retained".
function wins(a: VerifiedEvent, b: VerifiedEvent): boolean {
  return a.created_at > b.created_at || (a.created_at === b.created_at && a.id < b.id);
}

/**
 * `<kind>:<pubkey>:<d>` for replaceable and addressable events, as an `a` tag writes it; undefined otherwise.
 * Replaceable kinds use an empty d; addressable kinds use the first d tag's value, or empty without one.
 */
function addressOf(event: VerifiedEvent): string | undefined {
  const kindClass = classifyKind(event.kind);
  if (kindClass === "replaceable") return `${event.kind}:${event.pubkey}:`;
  if (kindClass !== "addressable") return undefined;
  const d = event.tags.find((tag) => tag[0] === "d")?.[1] ?? "";
  return `${event.kind}:${event.pubkey}:${d}`;
}

/**
 * Whether `request` is a deletion request that deletes `target` (NIP-09). Only events of the request's own pubkey
 * (WR-4), never another deletion request; an `e` tag by id, an `a` tag by address for versions up to the request's
 * `created_at`.
 */
function deletes(request: VerifiedEvent, target: VerifiedEvent): boolean {
  if (request.kind !== DELETION_KIND || target.kind === DELETION_KIND || request.pubkey !== target.pubkey) {
    return false;
  }
  const address = addressOf(target);
  return request.tags.some(
    ([name, value]) =>
      (name === "e" && value === target.id) ||
      (name === "a" && address !== undefined && value === address && target.created_at <= request.created_at),
  );
}

/** NIP-40: expired from the `expiration` timestamp on. A first `expiration` tag that is not a decimal integer is ignored. */
export function isExpired(event: VerifiedEvent, now: number): boolean {
  const value = event.tags.find((tag) => tag[0] === "expiration")?.[1];
  if (value === undefined || !/^\d+$/.test(value)) return false;
  return Number(value) <= now;
}
