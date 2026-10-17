# Zenith Vault threat model

What Zenith Vault protects, from whom, and the security invariants the code must keep, by ID (for example `EV-1`). It
covers security only; correctness, compatibility and design are reviewed against their own criteria.

**Keep it current.** A PR that adds an entry point, asset, trust boundary or accepted risk, or changes an invariant's
status, updates this file. IDs are never reused: an invariant that no longer applies is marked retired with the reason.

## Status of an invariant

Paths are relative to the repository root. **Enforced (main):** the cited source and test exist on `main`. **Planned
(stage):** not implemented; required before the stage ships. **Planned (importer, on hold):** belongs to the importers,
whose requirements and order are not decided yet.

A **Gap** note names a part that no test pins yet; that part does not count as enforced. Stages: 1 core, 2 storage, 3
protocol, 4 operations, 5 migration, 6 Blossom.

## How an invariant is pinned

Each invariant names how its test pins it.

- **Behavior:** a test drives the code with an input and checks the result (an `OK`, a `CLOSED`, a status code, the
  rows a `REQ` returns).
- **Source analysis:** a test reads the sources and fails on a forbidden shape. It suits a rule that must hold in every
  file, including code that no behavior test reaches. The test reads the sources with `import.meta.glob('?raw')`, skips
  test files, and also feeds its own patterns small fixtures that must be detected, so a pattern that silently stopped
  matching fails. The shapes are:
  - **forbidden import:** an `import`/`export ... from`/`import()` specifier, checked against an import graph;
  - **forbidden API:** a call or identifier matched by a regular expression;
  - **forbidden pattern:** a code shape, such as a template literal passed to `sql.exec`.
- **Log redaction:** a behavior test that injects marker values (event content, an AUTH event) into the code path,
  captures every `console` method, and asserts that no marker appears.
- **Schema:** a test that inspects the migrated SQLite schema with `PRAGMA` statements.
- **Configuration:** a setting in a configuration file (`pnpm-workspace.yaml`, a workflow, `wrangler.jsonc`) that no
  test exercises. An enforced part pinned by configuration alone cites no test.

`packages/core/src/threat-model.test.ts` checks this document: an _Enforced (main)_ invariant says how it is pinned;
one pinned by behavior, source analysis, log redaction or schema cites at least one test file; and every cited test
file exists and names the invariant's ID.

## Deployment assumptions

- One owner. The owner signs with a NIP-07 or NIP-46 signer; the owner's secret key is never on the server or in CI.
- The relay Worker accepts WebSocket connections and the owner's admin requests, and answers everything else itself.
  Its configuration is the owner's public key (`OWNER_PUBKEY`) and the relay URL clients connect to (`RELAY_URL`), both
  Worker variables, and the backup bucket binding (`BACKUPS`). These deployment values live in a gitignored file, not in
  this repository ([operations.md](operations.md)). One SQLite-backed Durable Object with a fixed name, the Vault DO,
  holds all relay state and uses the hibernation API.
- Blossom runs as a separate Worker that stores blobs in a private R2 bucket. Its allowlist comes from the Vault DO,
  which is the single source of truth for allowed keys.
- A backup cron copies events and blobs daily to a separate bucket with a 30-day bucket lock.
- Importers run as cron Workers with their keys in Worker secrets (on hold; see DATA-3).

**Out of scope:** a compromised Cloudflare account or platform, a compromised owner signer or machine (the owner's
secret key), the owner acting against their own vault, and hardware loss of R2 data. TLS is assumed between all
parties. A future read-only client of the vault over a Service Binding is not part of the plan; adding it adds an entry
point here, and it is a dedicated RPC, never a generic `REQ` proxy.

**Not built, on purpose:** proof of work, payments, IP reputation or CAPTCHA, fine-grained distributed rate limiting,
`AUTH` required for writes, a global replay cache for AUTH events (challenges are per connection), sharding the DO, KMS
key protection, encryption layered on top of R2, and search. Writes are closed by the allowlist, and reads by NIP-42.

## Assets

| ID  | Asset                                                                   | Why it matters                                                       |
| --- | ----------------------------------------------------------------------- | -------------------------------------------------------------------- |
| A1  | Stored events, current and replaced versions, and deletion requests     | They are signed: a leaked event is verifiably the owner's, forever   |
| A2  | The allowlist: keys, their roles and allowed kinds                      | Possession of a write grant lets a key add or delete events          |
| A3  | Importer keys and the importer's upstream read token                    | A leaked key writes within its kinds and uploads blobs until revoked |
| A4  | Blobs in R2 and the backups of events and blobs                         | Backups are the recovery path from deletion, bugs and key leaks      |
| A5  | Availability and cost: DO wake-ups, CPU, storage, R2 and request quotas | The vault is one DO, and the owner pays                              |

## Adversaries

| ID  | Adversary                                            | Capabilities                                                                         |
| --- | ---------------------------------------------------- | ------------------------------------------------------------------------------------ |
| R1  | An anonymous internet client                         | Opens WebSockets, sends arbitrary frames and HTTP requests, calls any route          |
| R2  | A holder of a Nostr key that is not on the allowlist | Signs valid events and AUTH events with its own key                                  |
| R3  | A holder of a leaked importer key                    | Signs valid events and Blossom tokens as that importer                               |
| R4  | A replayer of events signed elsewhere                | Resubmits events the owner or an importer published on other relays, and AUTH events |
| R5  | A holder of leaked logs or a leaked backup           | Reads files offline                                                                  |
| R6  | A party that learns a blob URL                       | Fetches the blob by its sha256                                                       |
| R7  | A compromised dependency, GitHub Action or fork PR   | Runs code in the build, CI or the deployed Workers                                   |

## Entry points

| Entry point                                 | Reached by | Authenticated by                                             | Status and code                                   |
| ------------------------------------------- | ---------- | ------------------------------------------------------------ | ------------------------------------------------- |
| Event verification for every received event | R1–R4      | id and signature (EV-1)                                      | main: `packages/core/src/event.ts`, `kind.ts`     |
| WebSocket `EVENT`                           | R1–R4      | signature, allowlist and the key's kinds; NIP-42 for NIP-70  | main: `packages/relay/src/vault.ts`               |
| WebSocket `REQ` and `CLOSE`                 | R1, R2     | NIP-42 as the owner                                          | main: `packages/relay/src/vault.ts`               |
| Live delivery                               | R1, R2     | NIP-42 as the owner                                          | main: `packages/relay/src/vault.ts`               |
| WebSocket `AUTH`                            | R1, R2, R4 | per-connection challenge, relay host, time window, signature | main: `packages/relay/src/vault.ts`               |
| NIP-11 document and other HTTP requests     | R1         | none; answered by the Worker without waking the DO           | main: `packages/relay/src/index.ts`, `nip11.ts`   |
| Admin route: allowlist changes and restore  | R1, R2     | the owner's NIP-98 signature                                 | main: `packages/relay/src/admin.ts`, `index.ts`   |
| Blossom upload                              | R1–R3      | BUD-11 token from the owner or an importer key               | Planned (6)                                       |
| Blossom list and delete                     | R1–R3      | BUD-11 token from the owner                                  | Planned (6)                                       |
| Blossom `GET` and `HEAD`                    | R1, R6     | none; the sha256 URL is the capability                       | Planned (6)                                       |
| Backup cron                                 | internal   | —                                                            | main: `packages/relay/src/index.ts`; blobs (6)    |
| Importer cron Workers                       | internal   | their own keys; a read-only upstream token                   | Planned (importer, on hold)                       |
| Build, CI and dependency updates            | R7         | lockfile, release age, pinned Actions                        | main: `pnpm-workspace.yaml`, `.github/workflows/` |

## Invariants

### Event validation (EV)

- **EV-1: an event is accepted only after its id and signature are recomputed.** `verifyEvent` takes the received
  JSON text and parses it again on every call; `verifyEventObject` takes an already parsed value. Both recompute the id
  and verify the BIP-340 signature with `@noble/curves` on every call, and cache nothing, so an object changed after a
  successful verification fails the next one. _Enforced (main):_ `verifyEvent` and `verifyEventObject` in
  `packages/core/src/event.ts`; `packages/core/src/event.test.ts` ("tampering": a changed id character, modified
  content, modified signature, another pubkey with and without a recomputed id, another key's signature, objects mutated
  after verification). _Pinned by behavior._ A received event is verified from its received text with `verifyEvent`, so
  that the size limit of RES-1 applies: `parseClientMessage` in `packages/core/src/message.ts` gives the event of an
  `EVENT` or `AUTH` message only as the exact text of that array element (`eventText`), never as a parsed value.
  _Enforced (main)_ for the text: `packages/core/src/message.test.ts` ("EV-1, RES-1": the element's exact text for any
  JSON value and formatting, and an event over 256 KiB in a message under 512 KiB refused by `verifyEvent`). _Enforced
  (main)_ for `AUTH`: `#auth` in `packages/relay/src/vault.ts`; `packages/relay/src/protocol.ws.test.ts` ("EV-1": a
  signature that does not verify, and an AUTH event over 256 KiB). _Pinned by behavior; and by source analysis,
  forbidden API:_ `packages/relay/src/source-analysis.test.ts` refuses `verifyEventObject` in every non-test file of
  `packages/relay/src` except `store.ts` (restore, ST-6). _Enforced (main)_ for `EVENT`: `#event` in
  `packages/relay/src/vault.ts`; `packages/relay/src/events.ws.test.ts` ("EV-1": a signature that does not verify, an
  id that does not match, an event over 256 KiB, and a field given twice, verified with the value JSON.parse keeps).
  _Pinned by behavior._
- **EV-2: the id follows NIP-01's serialization.** NIP-01: "The following characters in the content field must be
  escaped as shown, and all other characters must be included verbatim". Tag strings follow the same rule. An id
  computed with the `JSON.stringify` form, which escapes the other control characters as `\u00XX`, is also accepted, and
  only when a string contains such a character; both are deterministic hashes of the same fields under the same
  signature. A lone surrogate has no UTF-8 encoding and is rejected. _Enforced (main):_ `serializeEvent` and
  `computeEventId` in `packages/core/src/event.ts`; `packages/core/src/event.test.ts` ("serializeEvent /
  computeEventId", "control characters outside the seven NIP-01 escapes", "rejects a lone surrogate escape"). _Pinned by
  behavior._ _Gap: the expected serializations are written by hand and cross-checked with nostr-tools; no vector is an
  event signed outside this repository._ Vectors from real signed events (control characters, emoji, U+2028, lone
  surrogates): _Planned (1)._ The id is never computed with `JSON.stringify`: _Enforced (main):_
  `packages/core/src/source-analysis.test.ts` ("EV-7, EV-2"). _Pinned by source analysis, forbidden API:
  `JSON.stringify` (also `JSON["stringify"]` and an uncalled reference) outside comments in a non-test file of
  `packages/core/src`; the allowlist holds only `packages/core/src/canonical.ts`, which writes the stored JSON of an
  already verified event (ST-7), not an id._
- **EV-3: the event structure is checked before any use.** `id` and `pubkey` are 64 lowercase hex characters and `sig`
  128; `kind` is an integer from 0 to 65535 (NIP-01: "`<integer between 0 and 65535>`"); `created_at` is a non-negative
  integer; tags are arrays of one or more strings (NIP-01: "Each tag is an array of one or more strings"); `content` is
  a string. Unknown fields are ignored for the id and dropped from the verified result. Verification returns a
  rejection instead of throwing. _Enforced (main):_ `verifyParsed` in `packages/core/src/event.ts`;
  `packages/core/src/event.test.ts` ("structure"). _Pinned by behavior._
- **EV-4: `created_at` is at most 900 seconds in the future.** The past is not limited, so imported history is
  accepted. _Enforced (main):_ `maxFutureSeconds` in `packages/core/src/limits.ts`; `packages/core/src/event.test.ts`
  ("created_at window": `now + 900` accepted, `now + 901` rejected, `0` accepted). _Pinned by behavior._
- **EV-5: storage semantics come only from NIP-01's kind ranges.** Each kind is regular, replaceable, ephemeral,
  addressable or unknown by the ranges NIP-01 defines. _Enforced (main)_ for the classification: `classifyKind` in
  `packages/core/src/kind.ts`; `packages/core/src/kind.test.ts` (every range boundary). _Pinned by behavior._
  _Enforced (main)_ for storage: `apply` in `packages/relay/src/store.ts` takes how to store each class (each, versioned, never) from
  `classifyKind` through a `Record<KindClass, …>` table, so a class without an entry fails to compile;
  `packages/relay/src/store.test.ts` ("WR-5", "ST-1", and the reference model comparison over regular, unknown (45),
  replaceable, addressable and ephemeral kinds). _Pinned by behavior._
- **EV-6: an event already expired on receipt is rejected.** An event whose NIP-40 `expiration` has passed answers `OK`
  false with `invalid:`. An `expiration` equal to the current time has passed. An ephemeral event is the exception
  (NIP-40: "An expiration timestamp does not affect storage of ephemeral events"): it answers `OK` true, is never
  stored (WR-5), and is not delivered, because delivery checks the expiration when it sends (ST-3). _Enforced (main)_
  in the reference model: `apply` and `toOkResponse` in `packages/core/src/model.ts`; `packages/core/src/model.test.ts` ("EV-6"). _Pinned by
  behavior._ _Enforced (main)_ in storage: `EventStore.apply` in `packages/relay/src/store.ts`;
  `packages/relay/src/store.test.ts` ("EV-6", and the property that compares every write's outcome with the reference
  model). _Pinned by behavior._ _Enforced (main)_ for answering `EVENT`: `#event` in `packages/relay/src/vault.ts`
  answers each write outcome by `toOkResponse`; `packages/relay/src/events.ws.test.ts` ("EV-6": `OK` false with
  `invalid:`, nothing stored; and "ST-3, EV-6": an expired ephemeral event answered `OK` true, not stored and not
  delivered). _Pinned by behavior._
- **EV-7: `packages/core` is pure and depends on `@noble` only.** It imports no `cloudflare:*` module and no nostr-tools
  (nostr-tools' `verifyEvent` caches its result on the object, so it is used only in tests, as a cross-check). _Enforced
  (main):_ `packages/core/src/source-analysis.test.ts` ("EV-7, EV-2", "EV-7: declares only @noble packages"). _Pinned
  by source analysis, forbidden import: in an `import`, `export ... from` or `import()` of a non-test file of
  `packages/core/src`, any specifier other than a relative path (`./`, `../`) or one starting with `@noble/`, so
  `cloudflare:*` and nostr-tools are refused with every other package._ The same test checks that the `dependencies` of
  `packages/core/package.json` are exactly `@noble/curves` and `@noble/hashes`; nostr-tools is a `devDependency` only.

### Write authorization (WR)

- **WR-1: a write needs a valid signature, an allowlisted key and a kind that key may write.** `AUTH` is not required
  for writes (except WR-2). The owner may write every kind except 62; the blog importer only kinds 30023 and 5; the
  Mastodon importer only kinds 1 and 5. A key removed from the allowlist or marked retired writes nothing. Rejections
  use the standard `OK` prefixes: `blocked:` for a key that is not listed or is retired (NIP-01: "blocked: please
  register your pubkey at ..."), `restricted:` for a listed key writing a kind outside its grant (NIP-42: "the key used
  to perform it is still not allowed by the relay or is exceeding its authorization"). The owner is the one key given by the
  `OWNER_PUBKEY` configuration, parsed into a `VaultConfig` that the store requires; opening the store with another
  owner retires the previous one, and a configured owner that the allowlist records as revoked or retired keeps the
  store from opening (ST-8). An importer is added with at least one kind and never kind 62; the owner cannot be
  added, retired or revoked; a retired key cannot be added again. _Enforced (main)_ in storage: `checkWrite` and
  `parseVaultConfig` in `packages/relay/src/allowlist.ts`, called by `EventStore.apply` in
  `packages/relay/src/store.ts` before anything is stored, and the `allowed_keys` table;
  `packages/relay/src/authorization.test.ts` ("WR-1": the owner's kinds, the blog and Mastodon importers' kinds at each side of their grant, a key not listed, a
  retired and a revoked key, a key added later, a configured owner change, and every allowlist refusal). _Pinned by
  behavior._ _Enforced (main)_ for answering `EVENT`: `#event` in `packages/relay/src/vault.ts`, which answers a
  refusal by `toRejectionResponse`; `packages/relay/src/events.ws.test.ts` ("WR-1": the owner's event without `AUTH`,
  an importer within and outside its kinds, a key not listed, a retired key and kind 62, each checked in the store).
  _Pinned by behavior._
- **WR-2: a protected event is accepted only from its authenticated author.** An event with the `["-"]` tag is accepted
  only when the connection authenticated with NIP-42 as the event's `pubkey`. NIP-70: "The default behavior of a relay
  MUST be to reject any event that contains `["-"]`." The refusal is `auth-required:` on a connection without `AUTH`
  (NIP-70's example) and `restricted:` on one authenticated as another key. Only the keys that may write are recorded
  as authenticated (RD-1), and only they can write (WR-1). A `-` tag with more items is treated as protected too.
  _Enforced (main):_ `#event` and `isProtected` in `packages/relay/src/vault.ts`, checked before the store;
  `packages/relay/src/events.ws.test.ts` ("WR-2": without `AUTH`, authenticated as an importer or a key not on the
  allowlist, the owner's and an importer's own protected events accepted, each checked in the store). _Pinned by
  behavior._
- **WR-3: kind 62 is refused.** A request to vanish deletes the signer's events up to its `created_at`, deletion
  requests included (NIP-62: "Kind `62` requests a specific relay to delete everything, including NIP-09 Deletion
  Events, from the `.pubkey` until its `.created_at`"). That conflicts with keeping the signer's history, deletion
  requests included (ST-2, ST-4), so kind 62 answers `OK` false with `blocked:`, and NIP-62 is not listed in `supported_nips`. NIP-62 says "Paid relays or relays that restrict who can
  post MUST also follow the request to vanish"; Zenith does not implement NIP-62 at all. _Enforced (main)_ in storage:
  `checkWrite` in `packages/relay/src/allowlist.ts`, which refuses kind 62 before looking at the key, and grants that
  never include it; `packages/relay/src/authorization.test.ts` ("WR-3": from the owner, an importer and a key not
  listed). _Pinned by behavior._
- **WR-4: a deletion request affects only events of its own pubkey.** An importer key's kind 5 therefore never deletes
  the owner's events. NIP-09: "Relays SHOULD delete or stop publishing any referenced events that have an identical
  `pubkey` as the deletion request." _Enforced (main)_ in the reference model: `deletes` in
  `packages/core/src/model.ts`; `packages/core/src/model.test.ts` ("WR-4": `e` and `a` tags of another pubkey, in either
  order). _Pinned by behavior._ _Enforced (main)_ in storage: the deletion index (`deleted_ids`, `deleted_addresses`)
  and `#applyDeletion` and `#isDeleted` in `packages/relay/src/store.ts`; `packages/relay/src/store.test.ts` ("WR-4",
  and the reference model comparison). _Pinned by behavior._
- **WR-5: ephemeral events are never stored.** Kinds 20000 to 29999 are not stored, kind 22242 included. NIP-42: "Relays
  MUST exclude `kind: 22242` events from being broadcasted to any client." _Enforced (main)_ in the reference model:
  `apply` in `packages/core/src/model.ts`; `packages/core/src/model.test.ts` ("WR-5": kinds 20000, 22242 and 29999 not
  stored; 19999 and 30000 stored). _Pinned by behavior._ _Enforced (main)_ in storage: `EventStore.apply` in
  `packages/relay/src/store.ts`; `packages/relay/src/store.test.ts` ("WR-5", and the reference model comparison).
  _Pinned by behavior._ _Enforced (main)_ for delivery: `#event` in `packages/relay/src/vault.ts` delivers an
  ephemeral event live and never a kind 22242 event; `packages/relay/src/events.ws.test.ts` ("WR-5": an ephemeral event
  delivered and not stored; kind 22242 sent as `EVENT` neither stored nor delivered, to a `kinds` subscription or a
  tag one). _Pinned by behavior._

### Read authorization (RD)

- **RD-1: only the authenticated owner reads.** A `REQ` from an unauthenticated connection answers `CLOSED` with
  `auth-required:`; from a connection authenticated with another key, `CLOSED` with `restricted:`. A refused `REQ` is
  not registered. An `AUTH` with a valid signature for this connection from a key that is not the owner or an importer
  answers `OK` false with `restricted:`, and the connection counts as authenticated with another key. _Enforced
  (main):_ `#req` and `#auth` in `packages/relay/src/vault.ts`, which read who the connection authenticated as from its
  attachment (RD-3) and answer by a `Record` of refusals; `packages/relay/src/protocol.ws.test.ts` ("RD-1": an
  unauthenticated `REQ`, then `AUTH` with nothing delivered; `REQ` authenticated as a key not on the allowlist, an
  importer and a retired key; after each refusal, and after the `AUTH`, the connections' attachments hold no such
  subscription, while an accepted one is there). _Pinned by behavior._
- **RD-2: AUTH binds to this relay, this connection and now.** The relay sends a random challenge when the connection
  opens. An AUTH event is accepted only if it is kind 22242, its `created_at` is within ±600 seconds, its `challenge`
  tag equals the challenge this connection was sent, the host of its `relay` tag equals the configured relay host (not
  the request's `Host`), and its signature verifies (EV-1). The challenge stays valid for the connection (NIP-42: "The
  challenge is valid for the duration of the connection or until another challenge is sent by the relay"). _Enforced
  (main)_ for the verification: `verifyAuthEvent` in
  `packages/core/src/auth.ts`, which takes only a `VerifiedEvent` (EV-1); `packages/core/src/auth.test.ts` ("RD-2":
  kinds, `created_at` at ±600 and ±601 seconds and 11 minutes old, another or missing challenge, another host,
  subdomain, host suffix, userinfo, port and scheme). The relay host comparison lowercases the host, ignores ws versus
  wss, the path and a trailing slash, and drops the scheme's default port. _Pinned by behavior._ _Enforced (main)_ for
  the connection: `fetch` and `#auth` in `packages/relay/src/vault.ts` send 32 random bytes as the challenge when the
  connection opens and pass the configured `RELAY_URL` (`parseRelayConfig` in `packages/relay/src/config.ts`);
  `packages/relay/src/protocol.ws.test.ts` ("RD-2": a fresh challenge per connection, another connection's challenge,
  a `relay` tag naming the request's Host instead of the configured URL, 11 minutes old, another kind). _Pinned by
  behavior._
- **RD-3: authentication survives hibernation, and nothing else grants it.** The challenge, the authenticated pubkey
  and the subscriptions are kept in the WebSocket attachment and restored after hibernation. A connection without an
  attachment is unauthenticated. An attachment that is not of the expected shape counts as none. _Enforced (main):_
  `readState` and `writeState` in `packages/relay/src/connection.ts`, the only access to the attachment;
  `packages/relay/src/protocol.ws.test.ts` ("RD-3": after `evictDurableObject`, checked to give a new instance, the
  owner's connection is served a `REQ`, an unauthenticated one is refused, and the challenge still verifies; a
  connection whose attachment was removed after the owner's `AUTH` is closed on its next `REQ` (RES-4), with nothing
  registered). _Pinned by behavior (the DO is evicted, then the same connection sends `REQ`)._
- **RD-4: live delivery is authorized like a `REQ`.** Every delivery passes the RD-1 checks for the connection at
  sending time. A `REQ` sent before `AUTH` receives nothing after `AUTH`. Expired events (ST-3) are not delivered.
  _Enforced (main)_ for the registration: a refused `REQ` is never registered (RD-1), so nothing reaches it after
  `AUTH`; `packages/relay/src/protocol.ws.test.ts` ("RD-1: answers an unauthenticated REQ"). _Enforced (main)_ for
  live delivery: `#deliver` in `packages/relay/src/vault.ts` reads each open connection's attachment when it sends,
  and delivers only to a connection authenticated as the owner and within its deadline, for a subscription whose
  filters match, and only an event that is stored as current or ephemeral; `packages/relay/src/events.ws.test.ts`
  ("RD-4": a matching and a non-matching subscription, a duplicate, a refused write and a version stored as history,
  a replaced subscription and `CLOSE`, a `REQ` refused before `AUTH`, attachments rewritten after the `REQ` to drop
  the owner, keep only an importer or pass the deadline, and delivery after the DO is evicted). _Pinned by
  behavior._
- **RD-5: NIP-11 discloses only the minimum.** The document holds minimal relay information and the limits, sets
  `restricted_writes` to true and `auth_required` to false (writes do not need `AUTH`). It names no contact and no
  `pubkey`, so it does not disclose the owner. _Enforced (main):_ `packages/relay/src/nip11.ts`;
  `packages/relay/src/worker.test.ts` ("RD-5": the whole document, the owner's key absent, the CORS headers NIP-11
  requires). _Pinned by behavior._

### Storage semantics (ST)

- **ST-1: one rule decides the current version.** Replaceable and addressable events are keyed by pubkey, kind and
  `d_tag`, with `d_tag = ''` for replaceable kinds. The greater `created_at` wins, and on a tie the lower id. NIP-01:
  "In case of replaceable events with the same timestamp, the event with the lowest id (first in lexical order) should
  be retained". An id is stored once. _Enforced (main)_ for the reference model: `apply` and `query` in
  `packages/core/src/model.ts`; `packages/core/src/model.test.ts` ("ST-1", including fast-check properties over arrival
  order, resubmissions and created_at ties). _Enforced (main)_ for storage: `EventStore` in `packages/relay/src/store.ts`
  (`events.is_latest`), schema in `packages/relay/src/schema.ts`; `packages/relay/src/store.test.ts` ("ST-1", and the
  fast-check property that applies generated subsets, orders and resubmissions of a signed pool to the SQLite store and
  to the reference model and compares every outcome, the stored events and the `REQ` results),
  `packages/relay/src/schema.test.ts` ("ST-1"). _Pinned by behavior (generated event sequences compared with the
  reference model); schema: `events.id` is the primary key (`PRAGMA table_info`)._
- **ST-2: a deletion holds whatever the arrival order.** Deletion requests are stored and checked on every write: a
  deletion that arrives before its target, and an older version that arrives after a deletion, both stay deleted. A
  deleted id submitted again is rejected. An `a`-tag deletion applies only to replaceable and addressable kinds and only
  to versions with `created_at` up to the request's (NIP-09: "relays SHOULD delete all versions of the replaceable event
  up to the `created_at` timestamp of the deletion request event"). A deletion of a deletion has no effect (NIP-09:
  "Publishing a deletion request event against a deletion request has no effect."). _Enforced (main)_ for the reference
  model: `apply` and `deletes` in `packages/core/src/model.ts`; `packages/core/src/model.test.ts` ("ST-2", and the
  fast-check property that every arrival order of a pool with deletions, equal timestamps and expirations reaches the
  same stored events and `REQ` results). _Enforced (main)_ for storage: the deletion index in
  `packages/relay/src/schema.ts` and `packages/relay/src/store.ts`; `packages/relay/src/store.test.ts` ("ST-2", and the
  reference model comparison). _Pinned by behavior (generated sequences with reordering, equal timestamps and deletions
  first)._
- **ST-3: expired events are never served.** An event past its NIP-40 `expiration` is returned by neither `REQ` nor live
  delivery, whether or not it is still stored. _Enforced (main)_ for the reference model: `query` in
  `packages/core/src/model.ts`; `packages/core/src/model.test.ts` ("ST-3": not returned from the `expiration` time on,
  by `ids` either). _Enforced (main)_ for storage: `EventStore.query` in `packages/relay/src/store.ts`;
  `packages/relay/src/store.test.ts` ("ST-3", and the reference model comparison at two times). _Pinned by behavior._
  _Enforced (main)_ for live delivery: `#deliver` in `packages/relay/src/vault.ts` checks the reference model's
  `isExpired` when it sends, which also covers an ephemeral event (NIP-40: "An expiration timestamp does not affect
  storage of ephemeral events"); `packages/relay/src/events.ws.test.ts` ("ST-3, EV-6": an expired ephemeral event accepted
  and not delivered, one that expires later delivered). _Pinned by behavior._
- **ST-4: history is kept.** A replaced version is kept with `is_latest = 0`. A normal `REQ` returns current versions; a
  `REQ` by `ids` also returns replaced ones. If a frequently replaced kind accumulates too many versions, a per-kind
  retention count is the only thing that removes them. _Enforced (main)_ for the reference model: `query` in
  `packages/core/src/model.ts`; `packages/core/src/model.test.ts` ("ST-4"). _Enforced (main)_ for storage:
  `EventStore` in `packages/relay/src/store.ts`; `packages/relay/src/store.test.ts` ("ST-4", and the reference model
  comparison). _Pinned by behavior._ A new current version reads and writes a fixed number of rows however long the
  history is (A5): only the previous current version is marked as history; `packages/relay/src/store.test.ts` ("ST-1,
  ST-4: reads and writes as many rows", by the cursors' `rowsRead` and `rowsWritten`). No retention count exists yet.
- **ST-5: a retired key's events are history.** A retired key stays in the allowlist with the role `retired`. Its
  events stay stored and are not returned by a normal `REQ`. A new key's addressable events never replace the old key's,
  because the address includes the pubkey. A `REQ` by `ids` still returns them, as it returns replaced versions
  (ST-4). The events of a revoked key are treated the same way. _Enforced (main):_ `EventStore.query` in
  `packages/relay/src/store.ts`, which limits filters without `ids` to keys whose role is `owner` or `importer`;
  `packages/relay/src/authorization.test.ts` ("ST-5", "DATA-4"). _Pinned by behavior._
- **ST-6: restore accepts only signed events and rebuilds the same state.** The restore path is separate from `EVENT`
  and only the owner can use it (OPS-1). It restores the events and the allowlist (keys, roles, allowed kinds and
  retired state; a retired state cannot be derived from signed events). It checks each event's id and signature only,
  so events of revoked or retired keys, expired events, protected events and deletion requests are restored, and it
  rebuilds the current versions and the deletion index. A restored vault answers the same `REQ`s as before, and what was
  deleted stays deleted. _Enforced (main)_ for the path: `EventStore.restore` in `packages/relay/src/store.ts` restores
  into a store without events, in one transaction, checks each event with `verifyEventObject` without the received
  limits, stores it with the write semantics except expiration on receipt (ephemeral events are still not stored,
  WR-5), and refuses the whole restore on the first event that fails; `packages/relay/src/backup.test.ts` ("ST-6": the
  same events, allowlist and `REQ` results; events of other keys, expired, protected, kind 5 and kind 62 compared with
  the reference model; the deletion index rebuilt from deletion requests alone, so a deleted id and a version up to an
  `a` deletion are refused afterwards and a later version is stored; a forged event restoring nothing; and the fast-check property that exports a store built from
  generated writes, retirements and revocations, restores it into a new store and compares the stored events, the
  allowlist and `REQ` results at two times). _Pinned by behavior._ _Enforced (main)_ for its authorization: the admin
  route's `restore` command (OPS-1) names a backup by its id; `Vault.admin` in `packages/relay/src/vault.ts` reads it
  from the backup bucket with `readBackup` in `packages/relay/src/backup-bucket.ts`, which refuses an id outside
  `backups/<id>/`, a backup without a manifest and an object whose size or sha256 differs from the manifest, then calls
  `EventStore.restore`; `packages/relay/src/admin.test.ts` ("ST-6, ST-8": a backup written by another Vault DO's
  backup method restored into an empty relay with the same allowlist, `REQ` results and stored events; a second restore
  refused as `not-empty`; an unknown id, a malformed id and a changed object restoring nothing). _Pinned by behavior._
- **ST-7: the stored event is exactly the verified event.** The stored JSON is rebuilt from the seven verified fields
  (`id`, `pubkey`, `created_at`, `kind`, `tags`, `content`, `sig`) in a canonical form, not copied from the received
  text. Unknown fields are dropped, and a field given more than once is stored with the value that was verified. `REQ`
  responses, backups and restores use this canonical form. _Enforced (main)_ for the canonical form:
  `canonicalEventJson` in `packages/core/src/canonical.ts` and `canonicalEvents` in `packages/core/src/model.ts`;
  `packages/core/src/model.test.ts` ("ST-7": an event with an unknown field). _Enforced (main)_ for storage:
  `events.json` is written with `canonicalEventJson`, and `REQ` results are that column, in
  `packages/relay/src/store.ts`; `packages/relay/src/store.test.ts` ("ST-7": an event received with an unknown field
  and with `content` given twice is stored with the verified values; and the reference model comparison of the stored
  JSON). _Pinned by behavior: the stored JSON, parsed again, equals the verified event._ _Enforced (main)_ for the
  export and restore in storage: `EventStore.export` gives the `events.json` column as it is, and `EventStore.restore`
  stores it again through `canonicalEventJson`; `packages/relay/src/backup.test.ts` ("DATA-5", "ST-6"). _Enforced (main)_ for writing the backup: `writeBackup` in
  `packages/relay/src/backup-bucket.ts` writes the exported lines as they are; `packages/relay/src/admin.test.ts`
  ("DATA-5", "ST-7": the events object equals the exported canonical JSON byte for byte). _Pinned by behavior._
- **ST-8: restore never reverses a revocation or a retirement.** A key restored as retired stays retired, its events
  stay out of normal `REQ`s (ST-5), and a key revoked before the backup is not added back. No restore makes a key
  writable that the backup records as revoked or retired. Revoked keys are recorded (`revoked_keys`) and exported, so
  a restore knows them. When the store already has an allowlist, per key the more restrictive state wins: revoked over
  retired over writable; a writable key keeps the store's entry, so a backup never widens its kinds; and only the
  configured owner is the owner (a backup's other owner is restored as retired). When the store or the backup records
  the configured owner as revoked or retired, the restore is refused and nothing changes, and the store does not open
  with such a configuration (`EventStore.open`), since making that key the owner would reverse it.
  _Enforced (main)_ for the path:
  `mergeAllowlists` in `packages/relay/src/allowlist.ts`, used by `EventStore.restore` in `packages/relay/src/store.ts`;
  `packages/relay/src/backup.test.ts` ("ST-8": each merge rule, a restore that includes a retired key after which it
  stays retired and its events stay out of normal `REQ`s, a restore that does not list again a key the store revoked,
  and a backup that revoked the configured owner restoring nothing), `packages/relay/src/authorization.test.ts`
  ("ST-8": opening with a revoked, retired or previous owner configured), `packages/relay/src/validation.test.ts`
  ("ST-8": the allowlist of a backup checked against a Valibot schema, each malformed entry refusing the whole
  allowlist). _Pinned by behavior._ _Enforced (main)_ for
  backups of the allowlist and their restore through the admin route: `packages/relay/src/admin.test.ts` ("ST-6, ST-8":
  a production backup with a retired, a revoked and an active importer restored into an empty relay, after which the
  retired and the revoked key write nothing). _Pinned by behavior._

### Resources (RES)

- **RES-1: input is bounded before it is used.** Limits: WebSocket message 512 KiB, event 256 KiB (UTF-8 bytes of the
  raw JSON, checked before parsing), 2000 tags, 1 KiB per tag string, 20 subscriptions per connection, 10 filters per
  `REQ`, `limit` clamped to 500, subscription id 1 to 64 characters, WebSocket attachment 15 KiB (a `REQ` that would
  exceed it answers `CLOSED` with `invalid:`). The DO itself accepts WebSocket messages up to 32 MiB, so these limits are
  the application's. _Enforced (main)_ in `packages/core/src/limits.ts` and `packages/core/src/event.ts`, tested in
  `packages/core/src/event.test.ts` ("size limits", at and one past each bound), _pinned by behavior_: the event size
  in `verifyEvent` only (it measures the received text; `verifyEventObject` has no text to measure), and the tag count
  and tag size in both. The WebSocket entry gives `verifyEvent` the received text of the event (EV-1): _Enforced
  (main)_ for `AUTH` and `EVENT` (`packages/relay/src/protocol.ws.test.ts` and `events.ws.test.ts`, "EV-1, RES-1").
  _Enforced (main)_ for the message size: `parseClientMessage` in
  `packages/core/src/message.ts` measures the UTF-8 bytes before `JSON.parse`; `packages/core/src/message.test.ts`
  ("RES-1": at and one past 512 KiB, UTF-8 rather than UTF-16, oversized text that is not JSON) and
  `packages/relay/src/protocol.ws.test.ts` ("RES-1": a message over 512 KiB answered with `NOTICE`). _Enforced (main)_
  for the subscriptions, filters and attachment: `#req` in `packages/relay/src/vault.ts` (`maxSubscriptions` in
  `packages/core/src/limits.ts`, `parseFilters`, and `writeState` in `packages/relay/src/connection.ts`, which refuses a
  state over 15 KiB of JSON); `packages/relay/src/protocol.ws.test.ts` ("RES-1": the 21st subscription refused and a
  replacement accepted, 11 filters, a subscription that does not fit the attachment, which is not registered). _Pinned
  by behavior._
- **RES-2: queries never splice input into SQL.** Every value is a bound parameter. A query uses at most 90 bound
  parameters (the DO allows 100); longer `ids` or `authors` lists run in chunks. There is no prefix matching, and tag
  filters accept single-letter names only. _Enforced (main):_ SQL text is built only by the `sql` tag in
  `packages/relay/src/sql.ts`: its literal parts are the text, and each substituted value is bound as `?` (a
  substituted fragment is another `sql` tag result, so the only generated text is placeholders and literals).
  `EventStore` in `packages/relay/src/store.ts` runs every statement through one `exec` call that refuses more than 90
  parameters. A list of a filter (`ids`, `authors`, `kinds` or a tag) that does not fit runs in chunks whose results
  are merged and limited again; a filter that would need more than 256 chunked queries (many long tag lists) pages
  through the rows matching the lists that fit and checks the whole filter on each row. _Pinned by behavior:_
  `packages/relay/src/store.test.ts` ("RES-2": injection strings in `ids` and `#e`, built directly because
  `parseFilter` refuses non-hex values there, and in `#t`, return zero events without an error, and in `#d` find
  exactly the event that has them; 1000 `ids`, 100 `authors`, both together, 120 `kinds` with and without a limit, 100 `#t`
  values, and 19 or 20 tag lists, each compared with the reference model). _Pinned by source analysis, forbidden pattern:_
  `packages/relay/src/source-analysis.test.ts` ("RES-2"): the query argument of every `exec(` (also `exec<T>(`) in a
  non-test file of `packages/relay/src` must be a string literal or a template literal without `${`; the allowlist
  holds only `query.text` in `packages/relay/src/store.ts`, the text of a `sql` tag result. The same test allows
  reading `.sql` from a storage object only in `packages/relay/src/store.ts`.
- **RES-3: public HTTP requests never reach the DO.** The Worker answers NIP-11 and every other public HTTP request
  itself. The DO is woken only for a WebSocket upgrade on the relay's path and the messages on that connection, the
  alarm that closes connections past their RES-4 deadline, an admin request whose NIP-98 signature the Worker verified
  as the owner's (OPS-1), and the backup cron (DATA-5). The admin route and the cron may wake it because they act on
  the vault's state, which only the DO holds; the Worker checks an admin request completely first, so an anonymous
  request costs no DO wake-up.
  Connections use the hibernation API: `ctx.acceptWebSocket`, with the text `ping` answered `pong` by
  `setWebSocketAutoResponse` (Nostr defines no ping message; WebSocket protocol pings are answered by the runtime). The
  DO keeps no resident timer. _Enforced (main):_ the Worker in `packages/relay/src/index.ts`, which dispatches with a
  `switch` on the route that `routeOf` in `packages/relay/src/routes.ts` chooses by an exact comparison with the
  configuration, and `Vault` in `packages/relay/src/vault.ts`; `packages/relay/src/worker.test.ts` ("RES-3":
  NIP-11, a plain `GET`, a `POST`, another path and an upgrade on another path are answered with no Durable Object
  created, by `listDurableObjectIds`, also an unsigned admin request and a `GET` of the admin route),
  `packages/relay/src/routing.test.ts` ("RES-3": the relay's path with and without a query and on another host, a
  double or percent-encoded slash, a relay path below the root percent-encoded or in another case, and a `HEAD`,
  `POST` or `PUT` upgrade, each answered without the Vault namespace; `HEAD` answered with the status, headers and
  body of `GET` for NIP-11, a 404, the admin route's 405 and a 503),
  `packages/relay/src/admin.test.ts` ("RES-3": every refused admin request answered with no use of the Vault
  namespace), `packages/relay/src/protocol.ws.test.ts` ("RES-3": the ping answered).
  _Pinned by behavior; and by source analysis, forbidden API:_ `packages/relay/src/source-analysis.test.ts` refuses a
  `.accept()` call and `setInterval` in every non-test file of `packages/relay/src`, with an empty allowlist. _Checked
  in stage 4 by metrics (no DO wake-ups other than these reasons): Planned (4), checked after deployment._
- **RES-4: a connection not authenticated as an allowlisted key is closed after 30 seconds.** An `AUTH` with a key
  that is not on the allowlist neither lifts nor extends this deadline. Only the keys that may write (the owner and
  importers) lift it; a retired key does not. The deadline is kept in the attachment and enforced by the DO's alarm,
  which closes the connections past it with code 1008 and schedules the next deadline, and by the message handler, which
  closes a connection past it without verifying, storing or logging the message, so a client that ignores the close
  cannot keep using the connection; a connection without an attachment is past it. A message on a connection that is
  no longer open is ignored. _Enforced (main):_ `fetch`, `webSocketMessage`, `#auth` and `alarm` in
  `packages/relay/src/vault.ts`;
  `packages/relay/src/protocol.ws.test.ts` ("RES-4": an idle connection closed, one before its deadline kept, `AUTH`
  with a key not on the allowlist or a retired key then idle closed, the owner and an importer kept, a connection whose
  attachment was lost closed, an idle connection closed after the DO is evicted, an owner `AUTH` past the deadline
  answered by a close with no `OK` and no log before the alarm runs, and messages on a closed connection answered with
  nothing and no state change). _Pinned by behavior (the clock is moved past the deadline and the alarm run)._

### Media (MED)

- **MED-1: a Blossom token is checked fully before use.** A kind 24242 `Authorization` token is accepted only if its
  `created_at` is in the past, its `expiration` is in the future, its `t` tag matches the operation, a `server` tag names
  this server's domain (a token without one is refused), and for upload and delete an `x` tag matches the blob hash; the
  signature is verified last (EV-1). _Planned (6). Pinned by behavior._
- **MED-2: each Blossom operation has its own authorization.** Being on the allowlist is not enough: list and delete
  require the owner's key; upload accepts the owner and importer keys. The allowlist is the Vault DO's (WR-1). _Planned
  (6). Pinned by behavior._
- **MED-3: blobs are stored as received and addressed by their hash.** The Worker computes the sha256 and uses it as the
  key; an `X-SHA-256` that differs answers 409. The server never rewrites bytes, so removing location metadata is the
  client's job before upload. `GET` and `HEAD` need no token; an unknown hash answers 404. _Planned (6). Pinned by
  behavior._
- **MED-4: R2 is private.** Neither `r2.dev` nor a custom domain is enabled on the blob or backup buckets; blobs leave
  R2 only through the Blossom Worker. _Planned (6). Configuration; no test pins it._

### Data and keys (DATA)

- **DATA-1: logs carry no event content and no AUTH events.** Workers Logs keep `console` output for 7 days, so event
  bodies and AUTH events are never logged. Only `logEvent` in `packages/relay/src/log.ts` writes to the console, and
  every field it takes is typed by a closed set (an event name, an error class, a message type, a configuration
  error) or a number. _Enforced (main)_ for `AUTH`, `REQ`, malformed messages and an unexpected failure:
  `packages/relay/src/log-redaction.ws.test.ts` ("DATA-1": marker content, filters and AUTH events through accepted
  and refused `AUTH`, `REQ` and their failure paths log nothing; a failure whose error message holds markers logs the
  error class only). _Pinned by log redaction; and by source analysis, forbidden API:_
  `packages/relay/src/source-analysis.test.ts` refuses `console` in every non-test file of `packages/relay/src` except
  `log.ts`. _Enforced (main)_ for `EVENT` and live delivery: `packages/relay/src/log-redaction.ws.test.ts` ("DATA-1":
  marker content and filters through a stored, duplicate, ephemeral, kind 22242, refused, protected, expired, forged
  and oversized `EVENT` and their delivery log nothing; a failed delivery whose error message holds markers logs the
  error class only, closes that subscriber and still answers the sender). _Enforced (main)_ for the admin route and
  backups: `packages/relay/src/admin.test.ts` ("DATA-1": restoring a backup whose events hold marker content, backing up
  and a refused request log nothing, and the responses hold no event content and no part of the `Authorization`
  header; a failed cron run logs its reason code or error class only). An error thrown on a route fails the request
  and is not logged: `packages/relay/src/routing.test.ts` ("DATA-1": an error whose message is a marker fails the
  request and logs nothing at all). _Pinned by log redaction._ Cloudflare's own
  invocation logs record the request, and Tail Workers report its URL and headers with heuristic redaction, so they
  are turned off: `observability.logs.invocation_logs` is false in `packages/relay/wrangler.jsonc`
  ([operations.md](operations.md#logs-data-1)). _Pinned by configuration._ That the deployed Worker's logs hold only
  `logEvent` lines: _Planned (4), checked after deployment._
- **DATA-2: the owner's secret key is never on the server or in CI.** No code path takes it, and no secret holds it.
  The admin route verifies the owner's signature; the owner signs with their own signer ([operations.md](operations.md)).
  _Enforced (main)_ for the relay's configuration: `packages/relay/src/source-analysis.test.ts` ("DATA-2": `Env` in
  `packages/relay/src/env.d.ts` declares exactly `VAULT`, `BACKUPS`, `OWNER_PUBKEY` and `RELAY_URL`; `wrangler.jsonc`
  sets no variable and the deployment example exactly `OWNER_PUBKEY` and `RELAY_URL`; no source or configuration file
  holds an `nsec`, a `secrets` section or a name with `SECRET`, `PRIVATE` or `NSEC`), and `mergeDeployConfig` in `packages/relay/scripts/deploy-config.ts`, which `deploy.mjs` runs, refuses any other deployment key, a variable other than the two, and a route on another host (`packages/relay/src/deploy-config.test.ts`, "DATA-2"). _Pinned by source analysis._ CI and the other
  stages: _Planned (all stages). Pinned by review._
- **DATA-3: importer keys and the upstream token live only in Worker secrets.** Each source has its own key, limited to
  its kinds (WR-1) and to upload (MED-2). Nothing secret is stored in GitHub. _Planned (importer, on hold)._
- **DATA-4: a leaked key is revoked by removing it, and a key is rotated without rewriting history.** Removing a key
  from the allowlist revokes it at once (WR-1, OPS-2). To rotate an importer key, the new key is added, the source is
  imported again under it, and then the old key is marked retired (ST-5). A revoked key is recorded and is never
  listed again, by an add or a restore. Every allowlist operation reports whether it changed the allowlist, so that the
  caller closes every connection when it did (OPS-2). _Enforced (main)_ in storage: `addKey`, `retireKey` and
  `revokeKey` of `EventStore` in `packages/relay/src/store.ts`; `packages/relay/src/authorization.test.ts` ("DATA-4":
  a revoked key refused at once and never added again, its events kept as history, and a rotation in which the old
  key's addressable events do not replace the new key's). _Pinned by behavior._ _Enforced (main)_ for the admin route:
  the `add`, `retire` and `revoke` commands of `Vault.admin` in `packages/relay/src/vault.ts`;
  `packages/relay/src/admin.test.ts` ("OPS-1, DATA-4": each operation and each refusal, checked in the store).
  _Pinned by behavior._
- **DATA-5: backups cannot be deleted or overwritten for 30 days.** The stored event JSON (ST-7) and the allowlist (keys, roles,
  allowed kinds and retired state) are exported daily, and blobs are copied daily, to a separate bucket. The bucket lock is set before the first backup, and every object key
  includes the date, so each run writes new objects. Backups keep the stored form byte for byte. _Enforced (main)_ for
  the exported form: `EventStore.export` in `packages/relay/src/store.ts` gives every stored event, replaced versions
  included, as JSONL lines of the stored canonical JSON sorted by id, and the allowlist as one JSON document, both read
  to the end in one transaction (in memory, at the vault's size) so that a write after the export never joins it
  (`formatAllowlist` and `parseAllowlist` in `packages/relay/src/backup.ts`: keys, roles, kinds, and revoked keys);
  `packages/relay/src/backup.test.ts` ("DATA-5", including a key added and events written after the export). _Enforced
  (main)_ for writing events and the allowlist to the bucket: the cron's `scheduled` in `packages/relay/src/index.ts`
  calls `Vault.backup` in `packages/relay/src/vault.ts`, and `writeBackup` in `packages/relay/src/backup-bucket.ts`
  writes `backups/<id>/events.jsonl` and `allowlist.json`, each checked by R2 against its sha256, then
  `manifest.json` with their keys, sizes, sha256 and the event count. `<id>` is the run's UTC time and 64 random bits,
  so each run writes new keys and none relies on writing a key again. A failure logs a reason code only and fails the
  run. `packages/relay/src/admin.test.ts` ("DATA-5": two cron runs at the same time write two complete backups under
  different keys, the manifest's contents, a backup on the owner's request, a write the bucket refuses leaving no
  manifest, and a failed run's log), `packages/relay/src/validation.test.ts` ("DATA-5": a manifest of another version
  or id, naming another key, or with a malformed sha256, size or count refuses the backup). _Pinned by behavior._ The bucket lock (deletion and overwrite within retention
  refused): _Planned (4), checked after deployment_ ([operations.md](operations.md#backups-data-5)); the local runtime
  has no bucket lock. Restore drills: _Planned (4)._ Blobs: _Planned (6)._

### Operations (OPS)

- **OPS-1: the admin route is the owner's alone.** Allowlist changes and restores require a NIP-98 event signed by the
  owner whose URL, method and time match the request. The admin route is one URL under the relay URL
  (`RelayConfig.adminUrl`) that takes a `POST` of one JSON command of at most 4096 bytes. NIP-98: "Servers MUST perform
  the following checks": the kind 27235, `created_at` "within a reasonable time window (suggestion 60 seconds)", the
  `u` tag "exactly the same as the absolute request URL (including query parameters)", and the `method` tag. The body's
  sha256 in a `payload` tag is a SHOULD for clients and a MAY for servers in NIP-98; Zenith requires it for every
  request with a body, so a signed header authorizes one command. The `u` tag is compared with the configured admin
  URL, not the request's `Host`. The signature is verified by `verifyEvent` (EV-1). A failure answers 401 (NIP-98: "the
  server SHOULD respond with a 401 Unauthorized response code"), before the DO is woken (RES-3). _Enforced (main)_ for
  the verification: `verifyHttpAuth` in `packages/core/src/http-auth.ts`; `packages/core/src/http-auth.test.ts`
  ("OPS-1": the scheme, base64 and UTF-8, a forged signature, each kind, `created_at` at ±60 and ±61 seconds and 10
  minutes old, a `u` tag with another path, host, scheme, query or case, a method tag other than the request's, a
  missing or another body's `payload`; and a header built by nostr-tools' `nip98.getToken`). _Pinned by behavior._
  _Enforced (main)_ for the route: `authorizeAdminRequest` in `packages/relay/src/admin.ts`, the only place that creates
  the `AuthorizedCommand` that `Vault.admin` takes, called by the Worker in `packages/relay/src/index.ts` for a request
  whose URL equals the configured admin URL (`routeOf` in `packages/relay/src/routes.ts`); the command is checked
  against a Valibot schema (`parseAdminCommand`), and the `u` tag against `RelayConfig.adminUrl`;
  `packages/relay/src/admin.test.ts` ("OPS-1": a request signed by another key, without a header, with another URL,
  method, an old or future time, another kind, without a payload or with another body, with a forged signature, each
  answered 401 without the DO; another method, an oversized body, the admin path on another URL and a malformed
  command), `packages/relay/src/routing.test.ts` ("OPS-1": the admin URL with a trailing or double slash, a
  percent-encoded letter or slash, another case, a query, an empty query, another scheme, host or port answered 404
  without the DO; the forms the runtime normalizes to it still matched; a `u` tag naming the request's URL rather than
  the configured one refused), `packages/relay/src/validation.test.ts` ("OPS-1": each command shape accepted and
  refused). _Pinned by behavior; and by source analysis, forbidden pattern:_ `packages/relay/src/source-analysis.test.ts`
  refuses `as AuthorizedCommand` outside `admin.ts`. A signed request can be sent again within its 60 seconds; see
  the accepted risks.
- **OPS-2: an allowlist change closes every connection.** No subscription keeps the authority it had before the change.
  _Enforced (main)_ for the means: `closeAllConnections` of `Vault` in `packages/relay/src/vault.ts` closes every
  connection with code 1012; `packages/relay/src/protocol.ws.test.ts` ("OPS-2": an authenticated and an anonymous
  connection closed). _Enforced (main)_ for every allowlist change: `Vault.admin` in `packages/relay/src/vault.ts`
  calls it when an `add`, `retire` or `revoke` reports a change (an ok `AllowlistResult`), and when a restore reports
  `allowlistChanged`; `packages/relay/src/admin.ws.test.ts` ("OPS-2": the owner's subscribed connection and an
  anonymous one closed with 1012 after each change through the admin route, and kept when nothing changed). _Pinned by
  behavior._ _Gap: no test has an open connection during a restore, because a restore needs an empty vault and the
  WebSocket tests share one._
- **OPS-3: packages depend on lower layers and on listed libraries only.** `packages/core` depends on `@noble` only
  (EV-7). `packages/relay` and `packages/blossom` depend on `packages/core` and on a short allowlist of libraries, each
  with its reason ([decisions.md](decisions.md)): for relay, `valibot` (input shapes). Development
  dependencies of the scripts and the tests (such as `jsonc-parser` for the deployment script) are not part of the
  deployed Worker and are outside this list. _Enforced (main)_ for relay: `packages/relay/src/source-analysis.test.ts`
  ("OPS-3"). _Pinned by source analysis, forbidden import: in a non-test file of `packages/relay/src`, any specifier
  other than a relative path, `cloudflare:workers` or an own entry of `RUNTIME_DEPENDENCIES` (`@zenith/core`,
  `valibot`; a subpath such as `valibot/dist` is another entry, and a name of `Object.prototype` is none); and the `dependencies` of `packages/relay/package.json`
  are exactly those entries._ For blossom: _Planned (6)._

### Supply chain (SUP)

- **SUP-1: dependencies are locked and aged.** `pnpm-lock.yaml` pins every version, and `minimumReleaseAge` waits three
  days before a release is installable. A new dependency is added to the `catalog` of `pnpm-workspace.yaml` with an
  exact version that is past `minimumReleaseAge`, referenced as `catalog:`, and, for a runtime dependency, added to
  OPS-3's allowlist with its reason in [decisions.md](decisions.md). _Enforced (main):_ `pnpm-workspace.yaml`,
  `pnpm-lock.yaml`. _Pinned by configuration. Gap: no dependency audit runs in CI, and nothing checks that a catalog
  version is exact._
- **SUP-2: CI runs no unpinned or privileged code for forks.** GitHub Actions are pinned by commit SHA, workflows start
  with no permissions and grant them per job, and no workflow uses `pull_request_target`, so fork PRs get no secrets.
  _Enforced (main):_ `.github/workflows/`, linted by `.github/workflows/gha.yml`. _Pinned by configuration and workflow
  lint. Gap: no check fails when `pull_request_target` is added._

## Negative cases by stage

Each stage ships tests for these cases, named with the invariant IDs. Source analysis tests also check that their
patterns detect a small fixture of each forbidden shape.

| Stage        | Required negative cases                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1 core       | Serialization vectors from real signed events; AUTH from another host, with a stale challenge, with `created_at` 11 minutes old, with another connection's challenge; deletion before its target, older version after a deletion, `a` tag on a regular kind, deletion of a deletion, another pubkey's deletion. Source analysis: `cloudflare:*` or nostr-tools imported by core (EV-7), `JSON.stringify` for the id (EV-2)                                                                                                                                                   |
| 2 storage    | Blog key writing kind 0 or 1; revoked and retired keys; kind 62; deleted id resubmitted; injection strings in `#e` and `ids`; more than 90 `ids`; expired on receipt; restore of revoked, retired, expired, protected and kind 5 events giving the same `REQ` results; a restore that includes a retired key, after which it stays retired and its events stay out of normal `REQ`s (ST-8); an event with unknown fields or a repeated field stored with anything but the verified values (ST-7). Source analysis: interpolated SQL (RES-2). Schema: `events.id` primary key |
| 3 protocol   | Unauthenticated `REQ`; `REQ` authenticated as another key; `REQ` before `AUTH` then live events; hibernation then `REQ`; connection without attachment; `AUTH` with a key not on the allowlist, then idle past 30 seconds (RES-4); protected event from another key; expired event live; oversized message, filters, subscriptions and attachment; idle unauthenticated connection; kind 22242 stored or delivered. Source analysis: `.accept()`, `setInterval` (RES-3); package direction (OPS-3). Log redaction (DATA-1)                                                   |
| 4 operations | Admin request signed by another key; NIP-98 with another URL, method or an old time; connections surviving an allowlist change; deletion or overwrite of a backup within retention; restore of a production backup, including a retired key and its allowlist entry, into an empty relay (ST-6, ST-8); DO wake-ups for anything other than upgrades and their messages, the admin route and the backup cron; event content in logs                                                                                                                                           |
| 5 migration  | Imported events whose count, ids, signatures or raw differ from the final export                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| 6 Blossom    | Unauthenticated list and delete; importer token for list or delete; token without a `server` tag or for another domain; wrong `t`; expired token; `created_at` in the future; `x` that does not match; `X-SHA-256` mismatch; `GET` of an unknown hash; deleted blob restored from backup with a matching sha256. Source analysis: package direction (OPS-3)                                                                                                                                                                                                                  |

## IDs to check by change type

- **Event parsing, serialization or limits:** EV-1 to EV-4, EV-7, RES-1. Run the serialization vectors; keep the
  source analysis for `JSON.stringify` and core imports passing.
- **Write path (`EVENT`):** EV-1, EV-5, EV-6, WR-1 to WR-5, ST-1, ST-2, ST-7, RES-1, DATA-1. Test another key, a forbidden
  kind, a revoked key and a protected event.
- **Read path (`REQ`, live delivery):** RD-1 to RD-4, ST-3 to ST-5, RES-1, RES-2, DATA-1. Test unauthenticated, another
  key, and after hibernation.
- **Connection handling or the Worker router:** RD-2, RD-3, RES-3, RES-4, OPS-2. Keep the `.accept()` and `setInterval`
  analysis passing.
- **SQL, schema or migration:** RES-2, ST-1, ST-2, ST-4, ST-7. Keep the interpolated-SQL analysis and the schema test
  passing.
- **Logging:** DATA-1. Extend the log redaction markers to the new path.
- **Admin route, restore or backup:** OPS-1, OPS-2, ST-6, ST-7, ST-8, DATA-4, DATA-5.
- **Blossom:** MED-1 to MED-4, WR-1, DATA-5, OPS-3.
- **Importer:** DATA-3, DATA-4, WR-1, WR-4, MED-2.
- **New package or cross-package import:** EV-7, OPS-3.
- **New dependency or workflow:** SUP-1, SUP-2. Prefer a maintained, widely used library over custom security code,
  and record its version, age and license in the PR.

## Verification sources

NIP and BUD texts are quoted from their upstream repositories. Custom code is cross-checked against them: the NIP-01
serialization rule (`packages/core/src/event.test.ts`, with nostr-tools as a second implementation), and, as stages
land, signed events published outside this repository and `relay-tester` run against a local relay
(`docs/relay-tester.md`: how to run it, and the expected failures of checks that assume a public relay).

## Accepted risks

| Risk                                                                   | Why accepted                                                                                | Revisit when                                        |
| ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| A leaked event is verifiably the owner's and cannot be repudiated      | That is what signing is for; secrets are encrypted to the owner with NIP-44 before storing  | never                                               |
| Anyone can submit events that an allowlisted key signed elsewhere (R4) | Writes do not require `AUTH`; such events are the signer's own data                         | the vault must refuse events published elsewhere    |
| Blobs are readable by anyone who knows their sha256 URL                | Clients load images directly and cannot send credentials; secret media is encrypted first   | authenticated media fetch becomes interoperable     |
| The server does not remove location metadata from images               | Rewriting changes the hash; clients strip metadata before upload                            | a client uploads without stripping                  |
| NIP-62 requests to vanish are refused                                  | Honoring one would erase the signer's history up to the request, deletion requests included | the vault holds data a third party may ask to erase |
| Backups stay inside Cloudflare                                         | The risks covered are mistaken deletion, bugs and key leaks, not platform loss              | platform loss is in scope                           |
| An id computed with the `JSON.stringify` form is accepted (EV-2)       | Common clients compute ids this way; it is still a hash of the same fields                  | clients converge on the NIP-01 rule                 |
| A signed admin request can be sent again within 60 seconds (OPS-1)     | TLS hides the header, invocation logs are off, and every command is harmless to repeat      | a command that is not harmless to repeat is added   |

## How to use

- **PRs** list the invariant IDs they touch, and the status changes they make to this file.
- **Reviews:** the security lens of a review checks the IDs listed for the change type above, plus anything this model
  is missing.
- **Tests** name the invariant in the test name or a comment where practical (for example `// RD-1`), so
  `grep -rn 'RD-1' packages` shows its coverage.
- This document covers security only. It is not a correctness or design checklist.
