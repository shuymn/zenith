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

## Deployment assumptions

- One owner. The owner signs with a NIP-07 or NIP-46 signer; the owner's secret key is never on the server or in CI.
- The relay Worker accepts WebSocket connections and answers everything else itself. One SQLite-backed Durable Object
  with a fixed name, the Vault DO, holds all relay state and uses the hibernation API.
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
| WebSocket `EVENT`                           | R1–R4      | signature, allowlist and the key's kinds; NIP-42 for NIP-70  | Planned (3)                                       |
| WebSocket `REQ`, `CLOSE` and live delivery  | R1, R2     | NIP-42 as the owner                                          | Planned (3)                                       |
| WebSocket `AUTH`                            | R1, R2, R4 | per-connection challenge, relay host, time window, signature | Planned (1, 3)                                    |
| NIP-11 document and other HTTP requests     | R1         | none; answered by the Worker without waking the DO           | Planned (3)                                       |
| Admin route: allowlist changes and restore  | R1, R2     | the owner's NIP-98 signature                                 | Planned (4)                                       |
| Blossom upload                              | R1–R3      | BUD-11 token from the owner or an importer key               | Planned (6)                                       |
| Blossom list and delete                     | R1–R3      | BUD-11 token from the owner                                  | Planned (6)                                       |
| Blossom `GET` and `HEAD`                    | R1, R6     | none; the sha256 URL is the capability                       | Planned (6)                                       |
| Backup cron                                 | internal   | —                                                            | Planned (4, 6)                                    |
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
  after verification). _Pinned by behavior._ Every `EVENT` frame goes through `verifyEvent` on the received text (not
  `verifyEventObject`), so that the size limit of RES-1 applies: _Planned (3)._
- **EV-2: the id follows NIP-01's serialization.** NIP-01: "The following characters in the content field must be
  escaped as shown, and all other characters must be included verbatim". Tag strings follow the same rule. An id
  computed with the `JSON.stringify` form, which escapes the other control characters as `\u00XX`, is also accepted, and
  only when a string contains such a character; both are deterministic hashes of the same fields under the same
  signature. A lone surrogate has no UTF-8 encoding and is rejected. _Enforced (main):_ `serializeEvent` and
  `computeEventId` in `packages/core/src/event.ts`; `packages/core/src/event.test.ts` ("serializeEvent /
  computeEventId", "control characters outside the seven NIP-01 escapes", "rejects a lone surrogate escape"). _Pinned
  by behavior._ _Gap: the expected serializations are written by hand and cross-checked with nostr-tools; no vector is
  an event signed outside this repository._ Vectors from real signed events (control characters, emoji, U+2028, lone
  surrogates): _Planned (1)._ The id is never computed with `JSON.stringify`: _Planned (1), source analysis, forbidden
  API: a `JSON.stringify(` call in a non-test file of `packages/core/src`._
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
  `packages/core/src/kind.ts`; `packages/core/src/kind.test.ts` (every range boundary). _Pinned by behavior._ Its use by
  the write path: _Planned (2)._
- **EV-6: an event already expired on receipt is rejected.** An event whose NIP-40 `expiration` has passed answers `OK`
  false with `invalid:`. _Planned (2). Pinned by behavior._
- **EV-7: `packages/core` is pure and depends on `@noble` only.** It imports no `cloudflare:*` module and no nostr-tools
  (nostr-tools' `verifyEvent` caches its result on the object, so it is used only in tests, as a cross-check).
  _Planned (1), source analysis, forbidden import: a `cloudflare:*` or `nostr-tools` specifier in a non-test file of
  `packages/core/src`._ Today `packages/core/package.json` lists nostr-tools under `devDependencies` only, but no test
  pins it.

### Write authorization (WR)

- **WR-1: a write needs a valid signature, an allowlisted key and a kind that key may write.** `AUTH` is not required
  for writes (except WR-2). The owner may write every kind except 62; the blog importer only kinds 30023 and 5; the
  Mastodon importer only kinds 1 and 5. A key removed from the allowlist or marked retired writes nothing. Rejections
  use the standard `OK` prefixes. _Planned (2). Pinned by behavior._
- **WR-2: a protected event is accepted only from its authenticated author.** An event with the `["-"]` tag is accepted
  only when the connection authenticated with NIP-42 as the event's `pubkey`. NIP-70: "The default behavior of a relay
  MUST be to reject any event that contains `["-"]`." _Planned (3). Pinned by behavior._
- **WR-3: kind 62 is refused.** A request to vanish deletes the signer's events up to its `created_at`, deletion
  requests included (NIP-62: "Kind `62` requests a specific relay to delete everything, including NIP-09 Deletion
  Events, from the `.pubkey` until its `.created_at`"). That conflicts with keeping the signer's history, deletion
  requests included (ST-2, ST-4), so kind 62 answers `OK` false with `blocked:`, and NIP-62 is not listed in `supported_nips`. NIP-62 says "Paid relays or relays that restrict who can
  post MUST also follow the request to vanish"; Zenith does not implement NIP-62 at all. _Planned (2). Pinned by
  behavior._
- **WR-4: a deletion request affects only events of its own pubkey.** An importer key's kind 5 therefore never deletes
  the owner's events. NIP-09: "Relays SHOULD delete or stop publishing any referenced events that have an identical
  `pubkey` as the deletion request." _Planned (1, 2). Pinned by behavior._
- **WR-5: ephemeral events are never stored.** Kinds 20000 to 29999 are not stored, kind 22242 included. NIP-42:
  "Relays MUST exclude `kind: 22242` events from being broadcasted to any client." _Planned (2, 3). Pinned by
  behavior._

### Read authorization (RD)

- **RD-1: only the authenticated owner reads.** A `REQ` from an unauthenticated connection answers `CLOSED` with
  `auth-required:`; from a connection authenticated with another key, `CLOSED` with `restricted:`. A refused `REQ` is
  not registered. _Planned (3). Pinned by behavior._
- **RD-2: AUTH binds to this relay, this connection and now.** The relay sends a random challenge when the connection
  opens. An AUTH event is accepted only if it is kind 22242, its `created_at` is within ±600 seconds, its `challenge` tag
  equals the challenge this connection was sent, the host of its `relay` tag equals the configured relay host (not the
  request's `Host`), and its signature verifies (EV-1). _Planned (1)_ for the verification, _(3)_ for the connection.
  _Pinned by behavior._
- **RD-3: authentication survives hibernation, and nothing else grants it.** The challenge, the authenticated pubkey
  and the subscriptions are kept in the WebSocket attachment and restored after hibernation. A connection without an
  attachment is unauthenticated. _Planned (3). Pinned by behavior (the DO is evicted, then the same connection sends
  `REQ`)._
- **RD-4: live delivery is authorized like a `REQ`.** Every delivery passes the RD-1 checks for the connection at
  sending time. A `REQ` sent before `AUTH` receives nothing after `AUTH`. Expired events (ST-3) are not delivered.
  _Planned (3). Pinned by behavior._
- **RD-5: NIP-11 discloses only the minimum.** The document holds minimal relay information and the limits, sets
  `restricted_writes` to true and `auth_required` to false (writes do not need `AUTH`). _Planned (3). Pinned by
  behavior._

### Storage semantics (ST)

- **ST-1: one rule decides the current version.** Replaceable and addressable events are keyed by pubkey, kind and `d_tag`, with `d_tag = ''` for replaceable kinds. The greater `created_at` wins, and on a tie the lower id. NIP-01:
  "In case of replaceable events with the same timestamp, the event with the lowest id (first in lexical order) should
  be retained". An id is stored once. _Planned (1)_ for the reference model, _(2)_ for storage. _Pinned by behavior
  (generated event sequences compared with the reference model); schema: `events.id` is the primary key (`PRAGMA table_info`)._
- **ST-2: a deletion holds whatever the arrival order.** Deletion requests are stored and checked on every write: a
  deletion that arrives before its target, and an older version that arrives after a deletion, both stay deleted. A
  deleted id submitted again is rejected. An `a`-tag deletion applies only to replaceable and addressable kinds and only
  to versions with `created_at` up to the request's (NIP-09: "relays SHOULD delete all versions of the replaceable event
  up to the `created_at` timestamp of the deletion request event"). A deletion of a deletion has no effect (NIP-09:
  "Publishing a deletion request event against a deletion request has no effect."). _Planned (1, 2). Pinned by behavior
  (generated sequences with reordering, equal timestamps and deletions first)._
- **ST-3: expired events are never served.** An event past its NIP-40 `expiration` is returned by neither `REQ` nor live
  delivery, whether or not it is still stored. _Planned (2, 3). Pinned by behavior._
- **ST-4: history is kept.** A replaced version is kept with `is_latest = 0`. A normal `REQ` returns current versions;
  a `REQ` by `ids` also returns replaced ones. If a frequently replaced kind accumulates too many versions, a per-kind
  retention count is the only thing that removes them. _Planned (2). Pinned by behavior._
- **ST-5: a retired key's events are history.** A retired key stays in the allowlist with the role `retired`. Its
  events stay stored and are not returned by a normal `REQ`. A new key's addressable events never replace the old key's,
  because the address includes the pubkey. _Planned (2). Pinned by behavior._
- **ST-6: restore accepts only signed events and rebuilds the same state.** The restore path is separate from `EVENT`
  and only the owner can use it (OPS-1). It restores the events and the allowlist (keys, roles, allowed kinds and
  retired state; a retired state cannot be derived from signed events). It checks each event's id and signature only,
  so events of revoked or retired keys, expired events, protected events and deletion requests are restored, and it
  rebuilds the current versions and the deletion index. A restored vault answers the same `REQ`s as before, and what was
  deleted stays deleted. _Planned (2)_ for the path, _(4)_ for its authorization. _Pinned by behavior._
- **ST-7: the stored event is exactly the verified event.** The stored JSON is rebuilt from the seven verified fields
  (`id`, `pubkey`, `created_at`, `kind`, `tags`, `content`, `sig`) in a canonical form, not copied from the received
  text. Unknown fields are dropped, and a field given more than once is stored with the value that was verified. `REQ`
  responses, backups and restores use this canonical form. _Planned (2). Pinned by behavior: the stored JSON, parsed
  again, equals the verified event._
- **ST-8: restore never reverses a revocation or a retirement.** A key restored as retired stays retired, its events
  stay out of normal `REQ`s (ST-5), and a key revoked before the backup is not added back. No restore makes a key
  writable that the backup records as revoked or retired. _Planned (2)_ for the path, _(4)_ for backups of the
  allowlist. _Pinned by behavior (a restore that includes a retired key)._

### Resources (RES)

- **RES-1: input is bounded before it is used.** Limits: WebSocket message 512 KiB, event 256 KiB (UTF-8 bytes of the
  raw JSON, checked before parsing), 2000 tags, 1 KiB per tag string, 20 subscriptions per connection, 10 filters per
  `REQ`, `limit` clamped to 500, subscription id 1 to 64 characters, WebSocket attachment 15 KiB (a `REQ` that would
  exceed it answers `CLOSED` with `invalid:`). The DO itself accepts WebSocket messages up to 32 MiB, so these limits are
  the application's. _Enforced (main)_ in `packages/core/src/limits.ts` and `packages/core/src/event.ts`, tested in
  `packages/core/src/event.test.ts` ("size limits", at and one past each bound), _pinned by behavior_: the event size
  in `verifyEvent` only (it measures the received text; `verifyEventObject` has no text to measure), and the tag count
  and tag size in both. _Gap: nothing yet guarantees that the WebSocket entry passes received text to `verifyEvent`;
  Planned (3), see EV-1._ The other limits: _Planned (3)._
- **RES-2: queries never splice input into SQL.** Every value is a bound parameter. A query uses at most 90 bound
  parameters (the DO allows 100); longer `ids` or `authors` lists run in chunks. There is no prefix matching, and tag
  filters accept single-letter names only. _Planned (2). Pinned by behavior (injection strings in `#e` and `ids` return
  zero events without an error) and by source analysis, forbidden pattern: a template literal with a `${` substitution,
  or string concatenation, as the query argument of `sql.exec`; the only allowed generated text is a placeholder list
  built from a count._
- **RES-3: public HTTP requests never reach the DO.** The Worker answers NIP-11 and every other public HTTP request
  itself. The DO is woken only for a WebSocket upgrade and the messages on that connection, the admin route (OPS-1),
  and the backup cron (DATA-5). Connections use the hibernation API: `ctx.acceptWebSocket`, with pings answered by
  `setWebSocketAutoResponse`. The DO keeps no resident timer. _Planned (3). Pinned by source analysis, forbidden API: a
  WebSocket `.accept()` call (only `ctx.acceptWebSocket`), and `setInterval` in DO code; and checked in stage 4 by
  metrics (no DO wake-ups other than these reasons)._
- **RES-4: a connection not authenticated as an allowlisted key is closed after 30 seconds.** An `AUTH` with a key
  that is not on the allowlist neither lifts nor extends this deadline. _Planned (3). Pinned by behavior._

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
  bodies and AUTH events are never logged. _Planned (3, 4). Pinned by log redaction: marker content and a marker AUTH
  event pass through `EVENT`, `REQ`, `AUTH` and their failure paths, and no `console` call contains them._
- **DATA-2: the owner's secret key is never on the server or in CI.** No code path takes it, and no secret holds it.
  _Planned (all stages). Pinned by review._
- **DATA-3: importer keys and the upstream token live only in Worker secrets.** Each source has its own key, limited to
  its kinds (WR-1) and to upload (MED-2). Nothing secret is stored in GitHub. _Planned (importer, on hold)._
- **DATA-4: a leaked key is revoked by removing it, and a key is rotated without rewriting history.** Removing a key
  from the allowlist revokes it at once (WR-1, OPS-2). To rotate an importer key, the new key is added, the source is
  imported again under it, and then the old key is marked retired (ST-5). _Planned (2, 4). Pinned by behavior._
- **DATA-5: backups cannot be deleted or overwritten for 30 days.** The stored event JSON (ST-7) and the allowlist (keys, roles,
  allowed kinds and retired state) are exported daily, and blobs are copied daily, to a separate bucket. The bucket lock is set before the first backup, and every object key
  includes the date, so each run writes new objects. Backups keep the stored form byte for byte. _Planned (4)_ for events,
  _(6)_ for blobs. _Pinned by behavior (deletion and overwrite within retention are refused) and by restore drills._

### Operations (OPS)

- **OPS-1: the admin route is the owner's alone.** Allowlist changes and restores require a NIP-98 event signed by the
  owner whose URL, method and time match the request. _Planned (4). Pinned by behavior._
- **OPS-2: an allowlist change closes every connection.** No subscription keeps the authority it had before the change.
  _Planned (4). Pinned by behavior._
- **OPS-3: packages depend on lower layers only.** `packages/relay` and `packages/blossom` depend on `packages/core`;
  `packages/core` depends on no other package (EV-7). _Planned (3, 6). Pinned by source analysis, forbidden import: a
  specifier that crosses the package graph in the other direction._

### Supply chain (SUP)

- **SUP-1: dependencies are locked and aged.** `pnpm-lock.yaml` pins every version, and `minimumReleaseAge` waits three
  days before a release is installable. _Enforced (main):_ `pnpm-workspace.yaml`, `pnpm-lock.yaml`. _Pinned by
  configuration. Gap: no dependency audit runs in CI._
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
land, signed events published outside this repository and `relay-tester` run against a local relay (expected failures:
checks that assume a public relay).

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

## How to use

- **PRs** list the invariant IDs they touch, and the status changes they make to this file.
- **Reviews:** the security lens of a review checks the IDs listed for the change type above, plus anything this model
  is missing.
- **Tests** name the invariant in the test name or a comment where practical (for example `// RD-1`), so
  `grep -rn 'RD-1' packages` shows its coverage.
- This document covers security only. It is not a correctness or design checklist.
