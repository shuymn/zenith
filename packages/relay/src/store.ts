/**
 * Event storage on the SQLite database of the Vault Durable Object. Its results are defined to equal those of the
 * reference model in packages/core/src/model.ts (`referenceModel`), and the tests compare the two.
 */
import {
  canonicalEventJson,
  classifyKind,
  matchesFilter,
  resolveLimit,
  type Filter,
  type FilterLimits,
  type KindClass,
  type NostrEvent,
  type referenceModel,
  type VerifiedEvent,
} from "@zenith/core";
import { MIGRATIONS, MIGRATIONS_TABLE } from "./schema.ts";
import { list, MAX_BOUND_PARAMETERS, Sql, sql, type SqlValue } from "./sql.ts";

export type ApplyOutcome = referenceModel.ApplyOutcome;

/** How each kind class is stored, as in the reference model. `unknown` is stored like `regular`. */
const STORAGE: Record<KindClass, "each" | "versioned" | "never"> = {
  regular: "each",
  unknown: "each",
  replaceable: "versioned",
  addressable: "versioned",
  ephemeral: "never",
};

const DELETION_KIND = 5;
/** Tag names a filter can ask for (`#<letter>`); only these tags are indexed. */
const INDEXED_TAG_NAME = /^[a-zA-Z]$/;
/** `<kind>:<pubkey>:<d>` as the reference model writes an address: a kind without leading zeros, a lowercase pubkey. */
const ADDRESS = /^(0|[1-9][0-9]{0,4}):([0-9a-f]{64}):/;
/** Above this many chunked queries for one filter, the filter is answered by a scan instead (see `#scan`). */
const MAX_CHUNKED_QUERIES = 256;
const SCAN_PAGE_SIZE = 50;

type Address = { readonly pubkey: string; readonly kind: number; readonly d: string };
type Row = { id: string; created_at: number; json: string };
/** One list attribute of a filter: its values, and the condition for a chunk of them. */
type ListCondition = { readonly values: readonly SqlValue[]; readonly where: (chunk: readonly SqlValue[]) => Sql };

export class EventStore {
  // The only reference to the database: SQL runs through #run alone.
  readonly #storage: DurableObjectStorage;

  /** Opens the store on a Durable Object's storage and applies any pending migration. */
  constructor(storage: DurableObjectStorage) {
    this.#storage = storage;
    this.#migrate();
  }

  /** Applies one write at time `now` (unix seconds), atomically. The input already passed write authorization. */
  apply(event: VerifiedEvent, now: number): ApplyOutcome {
    const storage = STORAGE[classifyKind(event.kind)];
    // WR-5. NIP-40: "An expiration timestamp does not affect storage of ephemeral events."
    if (storage === "never") return "not-stored-ephemeral";
    const expiration = expirationOf(event);
    // EV-6. NIP-40: "Relays SHOULD drop any events that are published to them if they are expired."
    if (expiration !== null && expiration <= now) return "rejected-expired";
    return this.#storage.transactionSync(() => this.#write(event, storage === "versioned", expiration));
  }

  /**
   * The canonical JSON (ST-7) of the stored events a REQ with these filters returns at time `now`: per filter, the
   * matching events newest first (ties by lower id) up to the filter's limit; then the union, without duplicates, in
   * the same order. A filter with `ids` also returns replaced versions (ST-4). Expired events are never returned (ST-3).
   */
  query(filters: readonly Filter[], now: number, limits: Partial<FilterLimits> = {}): string[] {
    const rows = new Map<string, Row>();
    for (const filter of filters) {
      for (const row of this.#queryFilter(filter, now, resolveLimit(filter, limits))) rows.set(row.id, row);
    }
    return [...rows.values()].toSorted(compareRows).map((row) => row.json);
  }

  /** The canonical JSON (ST-7) of every stored event, replaced versions included, sorted by id. */
  canonicalEvents(): string[] {
    return this.#run<{ json: string }>(sql`SELECT json FROM events ORDER BY id`)
      .toArray()
      .map((row) => row.json);
  }

  #migrate(): void {
    this.#run(MIGRATIONS_TABLE);
    for (const migration of MIGRATIONS) {
      this.#storage.transactionSync(() => {
        const applied = this.#run(sql`SELECT 1 FROM schema_migrations WHERE version = ${migration.version}`);
        if (applied.toArray().length > 0) return;
        for (const statement of migration.statements) this.#run(statement);
        this.#run(sql`INSERT INTO schema_migrations (version) VALUES (${migration.version})`);
      });
    }
  }

  #write(event: VerifiedEvent, versioned: boolean, expiration: number | null): ApplyOutcome {
    if (this.#run(sql`SELECT 1 FROM events WHERE id = ${event.id}`).toArray().length > 0) return "duplicate";
    const address = versioned ? addressOf(event) : undefined;
    // ST-2: the stored deletion requests are checked on every write, so a deletion that arrived first still holds.
    if (this.#isDeleted(event, address)) return "rejected-deleted";

    // ST-1: a stored version that wins over this one makes it history (ST-4).
    const replaced = address !== undefined && this.#hasNewerVersion(event, address);
    this.#run(sql`INSERT INTO events (id, pubkey, kind, created_at, d_tag, is_latest, expiration, json)
      VALUES (${event.id}, ${event.pubkey}, ${event.kind}, ${event.created_at}, ${address?.d ?? null},
        ${replaced ? 0 : 1}, ${expiration}, ${canonicalEventJson(event)})`);
    if (address !== undefined && !replaced) {
      this.#run(sql`UPDATE events SET is_latest = 0
        WHERE pubkey = ${address.pubkey} AND kind = ${address.kind} AND d_tag = ${address.d} AND id <> ${event.id}`);
    }
    for (const [name, value] of event.tags) {
      // NIP-01: "Only the first value in any given tag is indexed."
      if (name === undefined || value === undefined || !INDEXED_TAG_NAME.test(name)) continue;
      this.#run(sql`INSERT OR IGNORE INTO event_tags (name, value, event_id) VALUES (${name}, ${value}, ${event.id})`);
    }
    if (event.kind === DELETION_KIND) this.#applyDeletion(event);
    return replaced ? "stored-as-history" : "stored";
  }

  /** Whether a stored deletion request deletes `event` (NIP-09): same pubkey (WR-4), never another deletion request. */
  #isDeleted(event: VerifiedEvent, address: Address | undefined): boolean {
    if (event.kind === DELETION_KIND) return false;
    const byId = this.#run(sql`SELECT 1 FROM deleted_ids WHERE event_id = ${event.id} AND pubkey = ${event.pubkey}`);
    if (byId.toArray().length > 0) return true;
    if (address === undefined) return false;
    // NIP-09: "relays SHOULD delete all versions of the replaceable event up to the `created_at` timestamp of the
    // deletion request event."
    const byAddress = this.#run(sql`SELECT 1 FROM deleted_addresses
      WHERE pubkey = ${address.pubkey} AND kind = ${address.kind} AND d_tag = ${address.d}
        AND until >= ${event.created_at}`);
    return byAddress.toArray().length > 0;
  }

  // NIP-01: "In case of replaceable events with the same timestamp, the event with the lowest id
  // (first in lexical order) should be retained".
  #hasNewerVersion(event: VerifiedEvent, address: Address): boolean {
    const newer = this.#run(sql`SELECT 1 FROM events
      WHERE pubkey = ${address.pubkey} AND kind = ${address.kind} AND d_tag = ${address.d}
        AND (created_at > ${event.created_at} OR (created_at = ${event.created_at} AND id < ${event.id}))
      LIMIT 1`);
    return newer.toArray().length > 0;
  }

  /** Records a stored deletion request in the deletion index and removes the events it deletes. */
  #applyDeletion(request: VerifiedEvent): void {
    const affected = new Map<string, Address>();
    const removed: string[] = [];
    for (const [name, value] of request.tags) {
      if (value === undefined) continue;
      if (name === "e") {
        this.#run(sql`INSERT OR IGNORE INTO deleted_ids (event_id, pubkey) VALUES (${value}, ${request.pubkey})`);
        const rows = this.#run<{
          id: string;
          pubkey: string;
          kind: number;
          d_tag: string | null;
        }>(sql`DELETE FROM events
          WHERE id = ${value} AND pubkey = ${request.pubkey} AND kind <> ${DELETION_KIND}
          RETURNING id, pubkey, kind, d_tag`);
        for (const row of rows) {
          removed.push(row.id);
          if (row.d_tag !== null) {
            const address = { pubkey: row.pubkey, kind: row.kind, d: row.d_tag };
            affected.set(JSON.stringify(address), address);
          }
        }
      } else if (name === "a") {
        const address = parseAddress(value);
        if (address === undefined || address.pubkey !== request.pubkey) continue;
        this.#run(sql`INSERT INTO deleted_addresses (pubkey, kind, d_tag, until)
          VALUES (${address.pubkey}, ${address.kind}, ${address.d}, ${request.created_at})
          ON CONFLICT (pubkey, kind, d_tag) DO UPDATE SET until = max(until, excluded.until)`);
        const rows = this.#run<{ id: string }>(sql`DELETE FROM events
          WHERE pubkey = ${address.pubkey} AND kind = ${address.kind} AND d_tag = ${address.d}
            AND created_at <= ${request.created_at}
          RETURNING id`);
        for (const row of rows) removed.push(row.id);
        affected.set(JSON.stringify(address), address);
      }
    }
    for (const id of removed) this.#run(sql`DELETE FROM event_tags WHERE event_id = ${id}`);
    for (const address of affected.values()) this.#updateLatest(address);
  }

  /** Marks the winning stored version of an address as current (ST-1) after versions were removed. */
  #updateLatest(address: Address): void {
    const match = sql`pubkey = ${address.pubkey} AND kind = ${address.kind} AND d_tag = ${address.d}`;
    this.#run(sql`UPDATE events
      SET is_latest = (id = (SELECT id FROM events WHERE ${match} ORDER BY created_at DESC, id ASC LIMIT 1))
      WHERE ${match}`);
  }

  /** Up to `limit` rows matching `filter`, newest first, ties by lower id. */
  #queryFilter(filter: Filter, now: number, limit: number): Row[] {
    // NIP-01: "When `limit` is zero, the relay MUST NOT return stored events for that filter."
    if (limit === 0) return [];
    const lists = listConditions(filter);
    // An empty list matches nothing.
    if (lists.some((condition) => condition.values.length === 0)) return [];

    const fixed: Sql[] = [sql`(e.expiration IS NULL OR e.expiration > ${now})`];
    // ST-4: a filter with ids also returns replaced versions.
    if (filter.ids === undefined) fixed.push(sql`e.is_latest = 1`);
    if (filter.since !== undefined) fixed.push(sql`e.created_at >= ${filter.since}`);
    if (filter.until !== undefined) fixed.push(sql`e.created_at <= ${filter.until}`);

    // RES-2: the parameters a query uses besides the list values are the fixed conditions, a tag name per tag list
    // and the limit; the list values share what is left of the limit, split into chunks when they do not fit.
    const overhead =
      Sql.join(fixed, sql``).params.length +
      lists.reduce((sum, condition) => sum + condition.where([]).params.length, 0) +
      1;
    const chunkSizes = planChunks(
      lists.map((condition) => condition.values.length),
      MAX_BOUND_PARAMETERS - overhead,
    );
    if (chunkSizes === undefined) return this.#scan(filter, fixed, lists, limit);

    const rows = new Map<string, Row>();
    for (const chunks of chunkProduct(lists, chunkSizes)) {
      const where = Sql.join([...fixed, ...chunks], sql` AND `);
      const query = sql`SELECT e.id, e.created_at, e.json FROM events AS e WHERE ${where}
        ORDER BY e.created_at DESC, e.id ASC LIMIT ${limit}`;
      for (const row of this.#rows(query)) rows.set(row.id, row);
    }
    return [...rows.values()].toSorted(compareRows).slice(0, limit);
  }

  /**
   * Answers a filter whose lists cannot be split into at most {@link MAX_CHUNKED_QUERIES} queries: pages through the
   * rows that match the fixed conditions and the lists that fit, newest first, and checks the whole filter on each.
   */
  #scan(filter: Filter, fixed: readonly Sql[], lists: readonly ListCondition[], limit: number): Row[] {
    const conditions = [...fixed];
    // Keyset (3) and page size (1) parameters are added per page.
    let used = Sql.join(fixed, sql``).params.length + 4;
    for (const condition of lists.toSorted((a, b) => a.values.length - b.values.length)) {
      const where = condition.where(condition.values);
      if (used + where.params.length > MAX_BOUND_PARAMETERS) break;
      used += where.params.length;
      conditions.push(where);
    }
    const found: Row[] = [];
    let after: Row | undefined;
    while (found.length < limit) {
      const keyset =
        after === undefined
          ? sql`1 = 1`
          : sql`(e.created_at < ${after.created_at} OR (e.created_at = ${after.created_at} AND e.id > ${after.id}))`;
      const where = Sql.join([...conditions, keyset], sql` AND `);
      const page = this.#rows(sql`SELECT e.id, e.created_at, e.json FROM events AS e WHERE ${where}
        ORDER BY e.created_at DESC, e.id ASC LIMIT ${SCAN_PAGE_SIZE}`);
      for (const row of page) {
        // The stored JSON is the canonical form of a verified event (ST-7).
        const event: NostrEvent = JSON.parse(row.json);
        if (found.length < limit && matchesFilter(event, filter)) found.push(row);
      }
      if (page.length < SCAN_PAGE_SIZE) break;
      after = page.at(-1);
    }
    return found;
  }

  #rows(query: Sql): Row[] {
    return this.#run<Row>(query).toArray();
  }

  /** Runs one statement. `T` is the row shape the statement's columns produce, as SqlStorage.exec takes it. */
  #run<T extends Record<string, SqlStorageValue> = Record<string, SqlStorageValue>>(query: Sql): SqlStorageCursor<T> {
    // RES-2: the planner keeps every query within the limit; exceeding it is a bug, not an input to recover from.
    if (query.params.length > MAX_BOUND_PARAMETERS) {
      throw new RangeError(`query uses ${query.params.length} bound parameters`);
    }
    return this.#storage.sql.exec<T>(query.text, ...query.params);
  }
}

function listConditions(filter: Filter): ListCondition[] {
  const lists: ListCondition[] = [];
  if (filter.ids !== undefined) {
    lists.push({ values: [...filter.ids], where: (chunk) => sql`e.id IN (${list(chunk)})` });
  }
  if (filter.authors !== undefined) {
    lists.push({ values: [...filter.authors], where: (chunk) => sql`e.pubkey IN (${list(chunk)})` });
  }
  if (filter.kinds !== undefined) {
    lists.push({ values: [...filter.kinds], where: (chunk) => sql`e.kind IN (${list(chunk)})` });
  }
  for (const [name, values] of filter.tags) {
    lists.push({
      values: [...values],
      where: (chunk) => sql`EXISTS (SELECT 1 FROM event_tags AS t
        WHERE t.event_id = e.id AND t.name = ${name} AND t.value IN (${list(chunk)}))`,
    });
  }
  return lists;
}

/**
 * Chunk sizes for lists of the given lengths whose sum fits `budget`, shrinking the largest chunk first; undefined
 * when no split fits or the split needs more than {@link MAX_CHUNKED_QUERIES} queries.
 */
function planChunks(lengths: readonly number[], budget: number): number[] | undefined {
  if (budget < lengths.length) return undefined;
  const sizes = [...lengths];
  let total = sizes.reduce((sum, size) => sum + size, 0);
  while (total > budget) {
    const largest = sizes.indexOf(Math.max(...sizes));
    sizes[largest] = (sizes[largest] ?? 1) - 1;
    total--;
  }
  const queries = lengths.reduce((product, length, index) => product * Math.ceil(length / (sizes[index] ?? 1)), 1);
  return queries <= MAX_CHUNKED_QUERIES ? sizes : undefined;
}

/** Every combination of one chunk per list, as the conditions of one query. */
function* chunkProduct(lists: readonly ListCondition[], sizes: readonly number[]): Generator<Sql[]> {
  const chunked = lists.map((condition, index) => {
    const size = sizes[index] ?? condition.values.length;
    const chunks: Sql[] = [];
    for (let start = 0; start < condition.values.length; start += size) {
      chunks.push(condition.where(condition.values.slice(start, start + size)));
    }
    return chunks;
  });
  function* combine(index: number, prefix: Sql[]): Generator<Sql[]> {
    const chunks = chunked[index];
    if (chunks === undefined) {
      yield prefix;
      return;
    }
    for (const chunk of chunks) yield* combine(index + 1, [...prefix, chunk]);
  }
  yield* combine(0, []);
}

// NIP-01: "Newer events should appear first, and in the case of ties the event with the lowest id
// (first in lexical order) should be first."
function compareRows(a: Row, b: Row): number {
  if (a.created_at !== b.created_at) return b.created_at - a.created_at;
  if (a.id === b.id) return 0;
  return a.id < b.id ? -1 : 1;
}

/**
 * NIP-40 timestamp of the first expiration tag, or null when it is not a decimal integer (the reference model ignores
 * it then). A value beyond Number.MAX_SAFE_INTEGER is stored as that, which no `now` reaches.
 */
function expirationOf(event: VerifiedEvent): number | null {
  const value = event.tags.find((tag) => tag[0] === "expiration")?.[1];
  if (value === undefined || !/^\d+$/.test(value)) return null;
  return Math.min(Number(value), Number.MAX_SAFE_INTEGER);
}

/** Replaceable kinds use an empty d; addressable kinds the first d tag's value, or empty without one. */
function addressOf(event: VerifiedEvent): Address {
  const d = classifyKind(event.kind) === "addressable" ? (event.tags.find((tag) => tag[0] === "d")?.[1] ?? "") : "";
  return { pubkey: event.pubkey, kind: event.kind, d };
}

/** The address an `a` tag names, when it can name a stored replaceable or addressable event. */
function parseAddress(value: string): Address | undefined {
  const match = value.match(ADDRESS);
  if (match === null) return undefined;
  const [prefix, kindText = "", pubkey = ""] = match;
  const kind = Number(kindText);
  if (STORAGE[classifyKind(kind)] !== "versioned") return undefined;
  const d = value.slice(prefix.length);
  // Replaceable kinds have the address `<kind>:<pubkey>:`.
  if (classifyKind(kind) === "replaceable" && d !== "") return undefined;
  return { pubkey, kind, d };
}
