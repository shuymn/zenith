# Operating Zenith Vault

How to deploy the relay, call its admin route, and check and restore backups. The security invariants these steps
keep are in [threat-model.md](threat-model.md) (OPS-1, OPS-2, DATA-1, DATA-2, DATA-5, ST-6, ST-8, RES-3).

Values in angle brackets are placeholders: `<BACKUP_BUCKET>` is the backup bucket's name, `<RELAY_HOST>` the relay's
host name (for example `relay.example.com`), `<OWNER_PUBKEY>` the owner's public key as 64 lowercase hex characters.
None of them is written in this repository.

Commands run from the repository root, with the tools from `mise.toml`: `npx wrangler` below means
`mise exec -- pnpm --filter @zenith/relay exec wrangler`.

## What runs

- The relay Worker `zenith-relay` and its one Durable Object, the Vault DO, which holds the events and the allowlist.
- A cron trigger at 03:17 UTC every day (`triggers.crons` in `packages/relay/wrangler.jsonc`) that writes a backup to
  the backup bucket (DATA-5).
- The backup bucket: a private R2 bucket with a 30-day bucket lock, bound as `BACKUPS`.
- The admin route at `https://<RELAY_HOST>/<relay path>/admin` (`https://<RELAY_HOST>/admin` when the relay URL's path
  is `/`), for the owner only (OPS-1).

The Worker has no `workers.dev` URL and no preview URLs (`workers_dev` and `preview_urls` are false): the route is the
only way in.

## One-time setup: the backup bucket and its lock

Create the bucket and lock it **before the first deployment**. A lock applies to the objects already in the bucket
and to new ones, but nothing protects a backup written before the lock exists. `pnpm run deploy` lists the bucket's
lock rules first and stops when the bucket does not exist; without that, `wrangler deploy` would create the bucket
itself, with no lock.

```sh
npx wrangler r2 bucket create <BACKUP_BUCKET>
# A rule over every object (an empty prefix) that keeps each object for 30 days: within that time it can be neither
# deleted nor overwritten.
npx wrangler r2 bucket lock add <BACKUP_BUCKET> backups-30-days "" --retention-days 30
npx wrangler r2 bucket lock list <BACKUP_BUCKET>
```

Leave public access off: neither `r2.dev` nor a custom domain is enabled on the bucket (MED-4). A bucket with lock
rules cannot be emptied until the rules are removed.

## The deployment file

`packages/relay/wrangler.jsonc` holds what is the same for every deployment: the bindings, the cron, the migrations
and the logging settings. The deployment values are in `packages/relay/wrangler.deploy.jsonc`, which git ignores:

```sh
cp packages/relay/wrangler.deploy.example.jsonc packages/relay/wrangler.deploy.jsonc
```

Then replace every value:

| Key                 | Value                                                                                      |
| ------------------- | ------------------------------------------------------------------------------------------ |
| `account_id`        | The Cloudflare account id (32 hex characters). Leave the key out to use wrangler's default |
| `routes`            | The relay's custom domain: `[{ "pattern": "<RELAY_HOST>", "custom_domain": true }]`        |
| `r2_buckets`        | `[{ "binding": "BACKUPS", "bucket_name": "<BACKUP_BUCKET>" }]`                             |
| `vars.OWNER_PUBKEY` | `<OWNER_PUBKEY>`: the owner's **public** key in hex, not an `npub` and never a secret key  |
| `vars.RELAY_URL`    | `wss://<RELAY_HOST>/`: the URL clients connect to                                          |

`packages/relay/scripts/deploy.mjs` refuses any other key and a route on another host than `RELAY_URL`'s, so the file cannot change the bindings, the cron or the
migrations, and it holds no secret (DATA-2): the owner signs with their own signer and the server never needs the
owner's secret key.

## Deploy

```sh
# Builds with the merged configuration and checks it, without uploading.
mise exec -- pnpm --filter @zenith/relay run deploy --dry-run
# Lists the bucket's lock rules (and stops if the bucket does not exist), then deploys.
mise exec -- pnpm --filter @zenith/relay run deploy
```

The script merges the deployment file into `wrangler.jsonc`, writes the result to
`packages/relay/.wrangler/deploy-config/wrangler.json` (ignored by git) and runs `wrangler deploy --config` on it.
Options after `deploy` go to `wrangler deploy`; `--profile <name>` goes to every wrangler command the script runs, which all read the merged configuration, so the lock check and the deployment use the same account. Do not put `--` before them: wrangler would take the options after a `--` as
positional arguments and deploy for real; the script refuses a `--` between options and drops one in front of them.

After the first deployment, open `wss://<RELAY_HOST>/` with a client, authenticate as the owner, and run a first
backup through the admin route (below) to check the bucket binding.

## Logs (DATA-1)

Workers Logs keep the Worker's `console` output, which only `logEvent` writes: an event name and reason codes. The
settings are in `wrangler.jsonc` under `observability`:

- `enabled: true` keeps that output for the retention of the plan (7 days on Workers Paid).
- `logs.invocation_logs: false` turns off the log Cloudflare writes for each invocation. Cloudflare's Workers Logs
  documentation says an invocation log "contains details such as the Request, Response, and related metadata"
  without listing the fields, and the Tail Workers documentation describes the request it reports as the URL and the
  headers, redacted only by heuristics ("subject to false positives and negatives"). The admin route's
  `Authorization` header carries a NIP-98 event signed by the owner, so invocation logs are turned off rather than
  trusted to redact it. Request bodies are not part of either.

Uncaught exceptions are still logged; the relay's code catches its failures and logs only their class.

To check after deploying: in the dashboard's Observability view for the Worker, the logs of an admin request and of
a cron run hold only `zenith.*` lines, with no request URL, header or body.

## The admin route (OPS-1)

The admin route takes a `POST` of one JSON command to the admin URL, with an `Authorization: Nostr <base64>` header:
a NIP-98 kind 27235 event signed by the owner whose `u` tag is the admin URL exactly, `method` tag is `POST`,
`payload` tag is the sha256 of the body in hex, and `created_at` is within 60 seconds of the server's clock. Anything
else is answered `401` without waking the Vault DO. The body is at most 4096 bytes.

| Command                                       | Effect                                                             |
| --------------------------------------------- | ------------------------------------------------------------------ |
| `{"op":"list"}`                               | The allowlist: keys, roles, kinds and revoked keys                 |
| `{"op":"add","pubkey":"<hex>","kinds":[1,5]}` | Adds an importer key with the kinds it may write (never 62)        |
| `{"op":"retire","pubkey":"<hex>"}`            | Marks a key retired: it writes nothing and its events stay history |
| `{"op":"revoke","pubkey":"<hex>"}`            | Removes a key and records it, so it is never listed again          |
| `{"op":"backup"}`                             | Writes a backup now and answers its id                             |
| `{"op":"restore","backup":"<id>"}`            | Restores the backup `<id>` from the bucket into an empty vault     |

An `add`, `retire` or `revoke` that changes the allowlist closes every WebSocket connection (OPS-2); clients
reconnect and authenticate again. A refused command answers its reason, for example `409` with
`{"ok":false,"op":"add","reason":"already-listed"}`.

With [nak](https://github.com/fiatjaf/nak), sign with the owner's signer: `--sec` takes a NIP-46 `bunker://` URL, so
the secret key stays in the signer. Keep the signer's URL out of shell history and files in this repository.

```sh
URL='https://<RELAY_HOST>/admin'
BODY='{"op":"list"}'
PAYLOAD=$(printf '%s' "$BODY" | shasum -a 256 | cut -d ' ' -f 1)
EVENT=$(nak event -k 27235 -c '' -t u="$URL" -t method=POST -t payload="$PAYLOAD" --sec '<OWNER_SIGNER>')
curl -sS -X POST "$URL" \
  -H "Authorization: Nostr $(printf '%s' "$EVENT" | base64 | tr -d '\n')" \
  -H 'Content-Type: application/json' \
  --data-binary "$BODY"
```

Send the request within 60 seconds of signing it. The same signed header could be sent again within that time with
the same body; every command is harmless to repeat (an allowlist change answers `unchanged`, a backup writes another
backup, a restore answers `not-empty`), so the relay keeps no record of used events.

## Backups (DATA-5)

Each run writes three objects under `backups/<id>/`, where `<id>` is the run's UTC time and 16 random hex characters,
for example `backups/2026-10-18T03-17-00.000Z-0123456789abcdef/`:

- `events.jsonl`: every stored event, replaced versions included, one canonical event JSON per line, sorted by id;
- `allowlist.json`: keys, roles, allowed kinds and revoked keys;
- `manifest.json`, written last: the id, the time, and the key, sha256 and size of the other two, and the number of
  events. A backup without a manifest is incomplete and cannot be restored.

Every run writes new keys, so the lock never has to refuse a write of the relay's own.

To check the backups:

1. In the dashboard, the bucket lists a new `backups/<date>...` prefix each day. A failed cron run logs
   `{"event":"zenith.backup.failed",...}` with a reason code and shows as a failed cron invocation.
2. Read a manifest: `npx wrangler r2 object get <BACKUP_BUCKET>/backups/<id>/manifest.json --remote --pipe`.
3. Check the lock with an object of its own, not a backup: write `canary/<date>` with
   `npx wrangler r2 object put <BACKUP_BUCKET>/canary/<date> --file <a small file> --remote`, then try
   `npx wrangler r2 object delete <BACKUP_BUCKET>/canary/<date> --remote` and the same `put` again. Both must be
   refused for 30 days.

## Restore (ST-6, ST-8)

A restore reads the backup from the bucket inside the Vault DO; the request names only its id. It restores only into a
vault that has no events, checks each object against the manifest, checks every event's id and signature, and merges
the allowlist so that no revoked or retired key becomes writable. When the merge changes the allowlist, every
connection is closed.

1. Pick the backup's `<id>` (the dashboard lists `backups/`; read its manifest to confirm the time and the count).
2. Make sure the relay to restore into has no events: a new deployment whose Vault DO has never stored an event, for
   example after a mistaken deletion of the whole vault. A vault with events answers `409` `not-empty`.
3. Send `{"op":"restore","backup":"<id>"}` to the admin route as above. The answer gives the number of events stored
   and whether the allowlist changed.
4. Connect as the owner and compare a few `REQ` results with what the backup should hold.

A restore that is refused changes nothing: `404` for an unknown id, `422` when an object does not match its manifest
or an event does not verify, `409` when the configured owner is revoked or retired in the store or the backup.
