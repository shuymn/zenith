import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { SCHEMA, type ColumnDeclaration, type IndexDeclaration, type SchemaDeclaration } from "./schema.ts";
import { openStore, publicKeyOf, signVerified, testSecretKey } from "./test-support.ts";

const OWNER = publicKeyOf(testSecretKey("A"));

async function withStorage<T>(callback: (storage: DurableObjectStorage) => T): Promise<T> {
  const stub = env.VAULT.get(env.VAULT.newUniqueId());
  return runInDurableObject(stub, (_instance, state) => callback(state.storage));
}

function rows<T extends Record<string, SqlStorageValue>>(
  storage: DurableObjectStorage,
  query: string,
  ...bindings: unknown[]
): T[] {
  return storage.sql.exec<T>(query, ...bindings).toArray();
}

/** The schema of the database as SQLite reports it, in the shape of {@link SCHEMA}. */
function inspect(storage: DurableObjectStorage): SchemaDeclaration {
  const tables: Record<string, SchemaDeclaration["tables"][string]> = {};
  const indexes: Record<string, IndexDeclaration> = {};
  const tableList = rows<{ name: string; wr: number }>(
    storage,
    "SELECT name, wr FROM pragma_table_list WHERE schema = 'main' AND type = 'table' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' AND name NOT LIKE '\\_cf\\_%' ESCAPE '\\' ORDER BY name",
  );
  for (const table of tableList) {
    const { name } = table;
    const columns = rows<{ name: string; type: string; notnull: number; pk: number }>(
      storage,
      'SELECT name, type, "notnull", pk FROM pragma_table_info(?) ORDER BY cid',
      name,
    ).map((column): ColumnDeclaration => ({
      name: column.name,
      type: column.type === "INTEGER" ? "INTEGER" : "TEXT",
      notNull: column.notnull === 1,
      pk: column.pk,
    }));
    tables[name] = { columns, withoutRowid: table.wr === 1 };
    for (const index of rows<{ name: string }>(
      storage,
      "SELECT name FROM pragma_index_list(?) WHERE origin = 'c'",
      name,
    )) {
      const indexName = index.name;
      const indexColumns = rows<{ name: string }>(
        storage,
        "SELECT name FROM pragma_index_info(?) ORDER BY seqno",
        indexName,
      );
      indexes[indexName] = { table: name, columns: indexColumns.map((column) => column.name) };
    }
  }
  return { tables, indexes };
}

function columnTypes(storage: DurableObjectStorage, table: string): string[] {
  return rows<{ type: string }>(storage, "SELECT type FROM pragma_table_info(?) ORDER BY cid", table).map(
    (row) => row.type,
  );
}

describe("schema", () => {
  it("ST-1: migrates to the declared schema, with events.id as the primary key", async () => {
    await withStorage((storage) => {
      const store = openStore(storage, OWNER);
      expect(store.canonicalEvents()).toEqual([]);
      expect(inspect(storage)).toEqual(SCHEMA);
      // Declared types are exactly TEXT or INTEGER, not only mapped to them.
      for (const [table, declaration] of Object.entries(SCHEMA.tables)) {
        expect(columnTypes(storage, table)).toEqual(declaration.columns.map((column) => column.type));
      }
      const pk = rows(storage, "SELECT name FROM pragma_table_info('events') WHERE pk > 0");
      expect(pk).toEqual([{ name: "id" }]);
    });
  });

  it("opens an already migrated database without changing it or its data", async () => {
    await withStorage((storage) => {
      const first = openStore(storage, OWNER);
      const event = signVerified({ kind: 1, created_at: 100 }, testSecretKey("A"));
      expect(first.apply(event, 1_000)).toEqual({ ok: true, outcome: "stored" });
      const second = openStore(storage, OWNER);
      expect(inspect(storage)).toEqual(SCHEMA);
      expect(rows(storage, "SELECT version FROM schema_migrations")).toEqual([{ version: 1 }, { version: 2 }]);
      expect(second.canonicalEvents()).toEqual(first.canonicalEvents());
      expect(second.apply(event, 1_000)).toEqual({ ok: true, outcome: "duplicate" });
    });
  });

  it("can run a migration's statements again when its version record is missing", async () => {
    await withStorage((storage) => {
      const store = openStore(storage, OWNER);
      const event = signVerified({ kind: 1, created_at: 100 }, testSecretKey("A"));
      store.apply(event, 1_000);
      storage.sql.exec("DELETE FROM schema_migrations");
      const reopened = openStore(storage, OWNER);
      expect(inspect(storage)).toEqual(SCHEMA);
      expect(reopened.canonicalEvents()).toEqual(store.canonicalEvents());
    });
  });
});
