/**
 * The storage schema: {@link SCHEMA} declares the tables and indexes the migrations must produce, and the schema test
 * compares it with the migrated database (`PRAGMA table_info`, `PRAGMA index_list`, `PRAGMA index_info`).
 */
import { sql, type Sql } from "./sql.ts";

export type ColumnDeclaration = {
  readonly name: string;
  readonly type: "TEXT" | "INTEGER";
  readonly notNull: boolean;
  /** 1-based position in the primary key, 0 when not part of it (as `PRAGMA table_info` reports). */
  readonly pk: number;
};

export type TableDeclaration = {
  readonly columns: readonly ColumnDeclaration[];
  readonly withoutRowid: boolean;
};

export type IndexDeclaration = { readonly table: string; readonly columns: readonly string[] };

export type SchemaDeclaration = {
  readonly tables: Readonly<Record<string, TableDeclaration>>;
  readonly indexes: Readonly<Record<string, IndexDeclaration>>;
};

function column(name: string, type: ColumnDeclaration["type"], notNull: boolean, pk = 0): ColumnDeclaration {
  return { name, type, notNull, pk };
}

export const SCHEMA: SchemaDeclaration = {
  tables: {
    schema_migrations: { columns: [column("version", "INTEGER", true, 1)], withoutRowid: false },
    // Every stored event, replaced versions included (ST-4). `json` is the canonical form (ST-7).
    events: {
      columns: [
        // ST-1: an id is stored once.
        column("id", "TEXT", true, 1),
        column("pubkey", "TEXT", true),
        column("kind", "INTEGER", true),
        column("created_at", "INTEGER", true),
        // '' for replaceable kinds, the first d tag's value (or '') for addressable kinds, NULL otherwise.
        column("d_tag", "TEXT", false),
        // 1 for regular and unknown kinds and for the current version of an address (ST-1), 0 for replaced versions.
        column("is_latest", "INTEGER", true),
        // NIP-40 timestamp of the first expiration tag when it is a decimal integer, NULL otherwise.
        column("expiration", "INTEGER", false),
        column("json", "TEXT", true),
      ],
      withoutRowid: false,
    },
    // The first value of each tag with a single-letter name; NIP-01: "Only the first value in any given tag is indexed."
    event_tags: {
      columns: [column("name", "TEXT", true, 1), column("value", "TEXT", true, 2), column("event_id", "TEXT", true, 3)],
      withoutRowid: true,
    },
    // `e` tags of stored deletion requests, keyed by the request's pubkey (WR-4, ST-2).
    deleted_ids: {
      columns: [column("event_id", "TEXT", true, 1), column("pubkey", "TEXT", true, 2)],
      withoutRowid: true,
    },
    // `a` tags of stored deletion requests: the address and the greatest request created_at (ST-2).
    deleted_addresses: {
      columns: [
        column("pubkey", "TEXT", true, 1),
        column("kind", "INTEGER", true, 2),
        column("d_tag", "TEXT", true, 3),
        column("until", "INTEGER", true),
      ],
      withoutRowid: true,
    },
  },
  indexes: {
    // REQ without authors or kinds, newest first.
    events_by_time: { table: "events", columns: ["is_latest", "created_at", "id"] },
    // REQ by kinds.
    events_by_kind: { table: "events", columns: ["kind", "created_at"] },
    // REQ by authors (and kinds); the current version of an address; a-tag deletions.
    events_by_address: { table: "events", columns: ["pubkey", "kind", "d_tag", "created_at", "id"] },
    // Removing the tags of a deleted event.
    event_tags_by_event: { table: "event_tags", columns: ["event_id"] },
  },
};

export type Migration = { readonly version: number; readonly statements: readonly Sql[] };

/** Applied in order inside one transaction each; a version already recorded in `schema_migrations` is skipped. */
export const MIGRATIONS: readonly Migration[] = [
  {
    version: 1,
    statements: [
      sql`CREATE TABLE IF NOT EXISTS events (
        id TEXT NOT NULL PRIMARY KEY,
        pubkey TEXT NOT NULL,
        kind INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        d_tag TEXT,
        is_latest INTEGER NOT NULL,
        expiration INTEGER,
        json TEXT NOT NULL
      )`,
      sql`CREATE INDEX IF NOT EXISTS events_by_time ON events (is_latest, created_at DESC, id)`,
      sql`CREATE INDEX IF NOT EXISTS events_by_kind ON events (kind, created_at DESC)`,
      sql`CREATE INDEX IF NOT EXISTS events_by_address ON events (pubkey, kind, d_tag, created_at DESC, id)`,
      sql`CREATE TABLE IF NOT EXISTS event_tags (
        name TEXT NOT NULL,
        value TEXT NOT NULL,
        event_id TEXT NOT NULL,
        PRIMARY KEY (name, value, event_id)
      ) WITHOUT ROWID`,
      sql`CREATE INDEX IF NOT EXISTS event_tags_by_event ON event_tags (event_id)`,
      sql`CREATE TABLE IF NOT EXISTS deleted_ids (
        event_id TEXT NOT NULL,
        pubkey TEXT NOT NULL,
        PRIMARY KEY (event_id, pubkey)
      ) WITHOUT ROWID`,
      sql`CREATE TABLE IF NOT EXISTS deleted_addresses (
        pubkey TEXT NOT NULL,
        kind INTEGER NOT NULL,
        d_tag TEXT NOT NULL,
        until INTEGER NOT NULL,
        PRIMARY KEY (pubkey, kind, d_tag)
      ) WITHOUT ROWID`,
    ],
  },
];

/** Created before any migration runs, so that the applied versions can be read. */
export const MIGRATIONS_TABLE = sql`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER NOT NULL PRIMARY KEY)`;
