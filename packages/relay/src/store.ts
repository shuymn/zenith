/**
 * Event storage on the SQLite database of the Vault Durable Object. Its results are defined to equal those of the
 * reference model in packages/core/src/model.ts (`referenceModel`), and the tests compare the two.
 */
import {
  canonicalEventJson,
  classifyKind,
  isHex32,
  matchesFilter,
  parseJsonText,
  resolveLimit,
  type Filter,
  type FilterLimits,
  type KindClass,
  type NostrEvent,
  type referenceModel,
  type VerifiedEvent,
  verifyEventObject,
} from "@zenith/core";
import {
  checkWrite,
  isKeyRole,
  isValidGrantKinds,
  mergeAllowlists,
  ownerConflict,
  OWNER_CONFLICTS,
  type OwnerConflict,
  type AllowedKey,
  type AllowlistResult,
  type AllowlistState,
  type KeyGrant,
  type KeyRole,
  type VaultConfig,
  type WriteRejection,
} from "./allowlist.ts";
import { formatAllowlist, parseAllowlist } from "./backup.ts";
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

export type WriteResult =
  | { readonly ok: true; readonly outcome: ApplyOutcome }
  | { readonly ok: false; readonly code: WriteRejection };

export type OpenResult =
  | { readonly ok: true; readonly store: EventStore }
  | { readonly ok: false; readonly code: OwnerConflict };

export const RESTORE_ERRORS = ["not-empty", "bad-allowlist", "bad-event", ...OWNER_CONFLICTS] as const;
export type RestoreError = (typeof RESTORE_ERRORS)[number];
/**
 * `events` counts the events stored. `allowlistChanged` true means the caller closes every connection (OPS-2).
 * `line` is the 1-based line of the event that failed verification.
 */
export type RestoreResult =
  | { readonly ok: true; readonly events: number; readonly allowlistChanged: boolean }
  | { readonly ok: false; readonly code: RestoreError; readonly line?: number };

/** What {@link EventStore.export} gives and {@link EventStore.restore} takes (DATA-5). */
export type Backup = {
  /** The lines of the events' JSONL: each a canonical event JSON (ST-7), without the line break. */
  readonly events: readonly string[];
  /** The allowlist as one JSON document. */
  readonly allowlist: string;
};

class RestoreAbort extends Error {
  readonly code: RestoreError;
  readonly line: number | undefined;
  constructor(code: RestoreError, line?: number) {
    super(code);
    this.code = code;
    this.line = line;
  }
}

/**
 * The vault's storage: events and the allowlist, on the SQLite database of the Vault Durable Object. Writes enter
 * through {@link apply}, which checks the allowlist first (WR-1); restores through {@link restore}, which checks only
 * the id and signature (ST-6). Its storage results equal those of the reference model in packages/core/src/model.ts
 * (`referenceModel`) for writes the allowlist accepts, and the tests compare the two.
 */
export class EventStore {
  // The only reference to the database: SQL runs through #run alone.
  readonly #storage: DurableObjectStorage;
  readonly #config: VaultConfig;

  private constructor(storage: DurableObjectStorage, config: VaultConfig) {
    this.#storage = storage;
    this.#config = config;
  }

  /**
   * Opens the store on a Durable Object's storage, applies any pending migration and makes the configured key the
   * one owner (a previous owner becomes retired). `now` is the time recorded for an owner listed for the first time.
   * ST-8: when the allowlist records the configured key as revoked or retired, nothing changes and the store does not
   * open.
   */
  static open(storage: DurableObjectStorage, config: VaultConfig, now: number): OpenResult {
    const store = new EventStore(storage, config);
    store.#migrate();
    const code = store.#storage.transactionSync(() => {
      const conflict = ownerConflict(store.listKeys(), config);
      if (conflict === undefined) store.#ensureOwner(now);
      return conflict;
    });
    return code === undefined ? { ok: true, store } : { ok: false, code };
  }

  /**
   * Applies one write at time `now` (unix seconds), atomically, after checking that the event's key may write its
   * kind (WR-1, WR-3). The event's id and signature were checked by its {@link VerifiedEvent} type.
   */
  apply(event: VerifiedEvent, now: number): WriteResult {
    return this.#storage.transactionSync((): WriteResult => {
      const code = checkWrite(event, this.#keyOf(event.pubkey));
      if (code !== undefined) return { ok: false, code };
      const storage = STORAGE[classifyKind(event.kind)];
      // WR-5. NIP-40: "An expiration timestamp does not affect storage of ephemeral events."
      if (storage === "never") return { ok: true, outcome: "not-stored-ephemeral" };
      const expiration = expirationOf(event);
      // EV-6. NIP-40: "Relays SHOULD drop any events that are published to them if they are expired."
      if (expiration !== null && expiration <= now) return { ok: true, outcome: "rejected-expired" };
      return { ok: true, outcome: this.#write(event, storage === "versioned", expiration) };
    });
  }

  /**
   * The canonical JSON (ST-7) of the stored events a REQ with these filters returns at time `now`: per filter, the
   * matching events newest first (ties by lower id) up to the filter's limit; then the union, without duplicates, in
   * the same order. A filter with `ids` also returns replaced versions (ST-4) and the events of keys that are retired
   * or no longer listed; any other filter returns only events of the owner and importers (ST-5). Expired events are
   * never returned (ST-3).
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

  /** Adds an importer key with the kinds it may write (WR-1). The owner comes from the configuration only. */
  addKey(pubkey: string, grant: KeyGrant, now: number): AllowlistResult {
    if (!isHex32(pubkey)) return { ok: false, code: "bad-pubkey" };
    if (!isValidGrantKinds(grant.kinds)) return { ok: false, code: "bad-kinds" };
    if (pubkey === this.#config.owner) return { ok: false, code: "owner-key" };
    return this.#storage.transactionSync((): AllowlistResult => {
      if (this.#isRevoked(pubkey)) return { ok: false, code: "revoked-key" };
      if (this.#keyOf(pubkey) !== undefined) return { ok: false, code: "already-listed" };
      const kinds = [...new Set(grant.kinds)].toSorted((a, b) => a - b);
      this.#insertKey({ pubkey, role: grant.role, kinds, addedAt: now });
      return { ok: true };
    });
  }

  /** Marks a key retired (ST-5, DATA-4): it writes nothing, and its events become history. */
  retireKey(pubkey: string): AllowlistResult {
    if (pubkey === this.#config.owner) return { ok: false, code: "owner-key" };
    return this.#storage.transactionSync((): AllowlistResult => {
      const key = this.#keyOf(pubkey);
      if (key === undefined) return { ok: false, code: "not-listed" };
      if (key.role === "retired") return { ok: false, code: "unchanged" };
      this.#run(sql`UPDATE allowed_keys SET role = 'retired' WHERE pubkey = ${pubkey}`);
      return { ok: true };
    });
  }

  /** Removes a key from the allowlist (DATA-4) and records it as revoked, so that it is never listed again (ST-8). */
  revokeKey(pubkey: string, now: number): AllowlistResult {
    if (pubkey === this.#config.owner) return { ok: false, code: "owner-key" };
    return this.#storage.transactionSync((): AllowlistResult => {
      if (this.#isRevoked(pubkey)) return { ok: false, code: "unchanged" };
      if (this.#keyOf(pubkey) === undefined) return { ok: false, code: "not-listed" };
      this.#run(sql`DELETE FROM allowed_keys WHERE pubkey = ${pubkey}`);
      this.#run(sql`INSERT INTO revoked_keys (pubkey, revoked_at) VALUES (${pubkey}, ${now})`);
      return { ok: true };
    });
  }

  /** The role of a key on the allowlist; undefined for a key that is not listed, a revoked one included. */
  roleOf(pubkey: string): KeyRole | undefined {
    return this.#keyOf(pubkey)?.role;
  }

  /** The allowlist, sorted by pubkey. */
  listKeys(): AllowlistState {
    const keys = this.#run<{ pubkey: string; role: string; kinds: string; added_at: number }>(
      sql`SELECT pubkey, role, kinds, added_at FROM allowed_keys ORDER BY pubkey`,
    )
      .toArray()
      .map(toAllowedKey);
    const revoked = this.#run<{ pubkey: string; revoked_at: number }>(
      sql`SELECT pubkey, revoked_at FROM revoked_keys ORDER BY pubkey`,
    )
      .toArray()
      .map((row) => ({ pubkey: row.pubkey, revokedAt: row.revoked_at }));
    return { keys, revoked };
  }

  /**
   * The vault as a backup (DATA-5): every stored event, replaced versions included, in canonical form sorted by id,
   * and the allowlist. Both are read to the end in one transaction before returning, so the backup is one consistent
   * state and no later write joins it. A vault this size fits in memory.
   */
  export(): Backup {
    return this.#storage.transactionSync(() => ({
      events: this.canonicalEvents(),
      allowlist: formatAllowlist(this.listKeys()),
    }));
  }

  /**
   * Rebuilds an empty store from a backup (ST-6), in one transaction: nothing is restored unless everything is.
   * Each event is checked for its id and signature only; the allowlist, expiration on receipt and NIP-70 do not
   * apply, so events of revoked or retired keys, expired, protected and deletion events come back. They are stored
   * with the usual semantics, which rebuilds the current versions and the deletion index. The allowlist is merged by
   * {@link mergeAllowlists}, so a restore never lists a revoked key again or makes a retired one writable (ST-8).
   */
  restore(backup: Backup): RestoreResult {
    const parsed = parseAllowlist(backup.allowlist);
    if (!parsed.ok) return parsed;
    const allowlist = parsed.state;
    try {
      return this.#storage.transactionSync((): RestoreResult => {
        if (this.#run(sql`SELECT 1 FROM events LIMIT 1`).toArray().length > 0) throw new RestoreAbort("not-empty");
        let count = 0;
        let line = 0;
        for (const text of backup.events) {
          line++;
          const event = verifyRestoredEvent(text);
          if (event === undefined) throw new RestoreAbort("bad-event", line);
          const storage = STORAGE[classifyKind(event.kind)];
          // WR-5: an ephemeral event is never stored, whatever its source.
          if (storage === "never") continue;
          const outcome = this.#write(event, storage === "versioned", expirationOf(event));
          if (outcome === "stored" || outcome === "stored-as-history") count++;
        }
        const before = this.listKeys();
        const result = mergeAllowlists(before, allowlist, this.#config);
        if (!result.ok) throw new RestoreAbort(result.code);
        const merged = result.state;
        const allowlistChanged = formatAllowlist(merged) !== formatAllowlist(before);
        if (allowlistChanged) this.#replaceAllowlist(merged);
        return { ok: true, events: count, allowlistChanged };
      });
    } catch (error) {
      if (error instanceof RestoreAbort) {
        return error.line === undefined
          ? { ok: false, code: error.code }
          : { ok: false, code: error.code, line: error.line };
      }
      throw error;
    }
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

  /** The configured key is the one owner; any other owner becomes retired. */
  #ensureOwner(now: number): void {
    const owner = this.#config.owner;
    const current = this.#keyOf(owner);
    if (current?.role === "owner") return;
    for (const key of this.listKeys().keys) {
      if (key.role === "owner") this.#run(sql`UPDATE allowed_keys SET role = 'retired' WHERE pubkey = ${key.pubkey}`);
    }
    this.#run(sql`DELETE FROM allowed_keys WHERE pubkey = ${owner}`);
    this.#insertKey({ pubkey: owner, role: "owner", addedAt: current?.addedAt ?? now });
  }

  #keyOf(pubkey: string): AllowedKey | undefined {
    const [row] = this.#run<{ pubkey: string; role: string; kinds: string; added_at: number }>(
      sql`SELECT pubkey, role, kinds, added_at FROM allowed_keys WHERE pubkey = ${pubkey}`,
    ).toArray();
    return row === undefined ? undefined : toAllowedKey(row);
  }

  #isRevoked(pubkey: string): boolean {
    return this.#run(sql`SELECT 1 FROM revoked_keys WHERE pubkey = ${pubkey}`).toArray().length > 0;
  }

  #insertKey(key: AllowedKey): void {
    const kinds = JSON.stringify(key.role === "owner" ? [] : key.kinds);
    this.#run(sql`INSERT INTO allowed_keys (pubkey, role, kinds, added_at)
      VALUES (${key.pubkey}, ${key.role}, ${kinds}, ${key.addedAt})`);
  }

  #replaceAllowlist(state: AllowlistState): void {
    this.#run(sql`DELETE FROM allowed_keys`);
    this.#run(sql`DELETE FROM revoked_keys`);
    for (const key of state.keys) this.#insertKey(key);
    for (const entry of state.revoked) {
      this.#run(sql`INSERT INTO revoked_keys (pubkey, revoked_at) VALUES (${entry.pubkey}, ${entry.revokedAt})`);
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
      // Only the previous current version becomes history: the first other row of the address in the order of
      // events_by_address, so one row is read and written however long the history is.
      this.#run(sql`UPDATE events SET is_latest = 0 WHERE id = (SELECT id FROM events
        WHERE pubkey = ${address.pubkey} AND kind = ${address.kind} AND d_tag = ${address.d} AND id <> ${event.id}
          AND is_latest = 1
        ORDER BY created_at DESC, id ASC LIMIT 1)`);
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
  // Only the stored winner is compared, the first row of the address in the order of events_by_address, so one row
  // is read however long the history is.
  #hasNewerVersion(event: VerifiedEvent, address: Address): boolean {
    const [winner] = this.#run<{ created_at: number; id: string }>(sql`SELECT created_at, id FROM events
      WHERE pubkey = ${address.pubkey} AND kind = ${address.kind} AND d_tag = ${address.d}
      ORDER BY created_at DESC, id ASC LIMIT 1`).toArray();
    if (winner === undefined) return false;
    return winner.created_at > event.created_at || (winner.created_at === event.created_at && winner.id < event.id);
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
    // ST-4: a filter with ids also returns replaced versions. ST-5: any other filter returns only events of keys
    // that may write, so the events of retired and revoked keys are history.
    if (filter.ids === undefined) {
      fixed.push(sql`e.is_latest = 1`);
      fixed.push(sql`e.pubkey IN (SELECT pubkey FROM allowed_keys WHERE role IN ('owner', 'importer'))`);
    }
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

function toAllowedKey(row: { pubkey: string; role: string; kinds: string; added_at: number }): AllowedKey {
  if (!isKeyRole(row.role)) throw new Error("allowed_keys holds an unknown role");
  if (row.role === "owner") return { pubkey: row.pubkey, role: "owner", addedAt: row.added_at };
  const kinds: unknown = JSON.parse(row.kinds);
  if (!Array.isArray(kinds)) throw new Error("allowed_keys holds malformed kinds");
  const values: unknown[] = kinds;
  return {
    pubkey: row.pubkey,
    role: row.role,
    kinds: values.filter((kind): kind is number => typeof kind === "number"),
    addedAt: row.added_at,
  };
}

/** ST-6: a restored event is checked for its id and signature only, not the limits a received event meets. */
function verifyRestoredEvent(text: string): VerifiedEvent | undefined {
  const parsed = parseJsonText(text);
  if (!parsed.ok) return undefined;
  const unlimited = Number.POSITIVE_INFINITY;
  const result = verifyEventObject(parsed.value, {
    limits: { maxTags: unlimited, maxTagValueBytes: unlimited, maxFutureSeconds: unlimited },
  });
  return result.ok ? result.event : undefined;
}
