# Running relay-tester against a local relay

[relay-tester](https://github.com/mikedilger/relay-tester) is a conformance suite for Nostr relays. It assumes a relay
that is open to the public, so against Zenith Vault, a private relay, many of its checks fail by design. This page is
how to run it and how to read the result. It is a manual check; it does not run in CI.

## Run it

relay-tester is built from source with Cargo. The run recorded below used commit
`a8483f82f4965841faa92fae02105d4fd67d9117`.

1. Build it, in a directory outside this repository:

   ```sh
   git clone https://github.com/mikedilger/relay-tester.git
   cd relay-tester
   git checkout a8483f82f4965841faa92fae02105d4fd67d9117
   cargo build --release --locked
   ```

2. Make two throwaway keys with `./target/release/generate-keypair`. The first one is the owner; the second plays a
   key that is not on the allowlist (the allowlist cannot be changed yet, stage 4). Never use a real key: relay-tester
   says it does not handle the secret key with care.

3. Start a fresh local relay from `packages/relay`, with the first key as the owner and its own state directory:

   ```sh
   pnpm exec wrangler dev --local --port 8799 --persist-to <empty directory> \
     --var OWNER_PUBKEY:<first key's public hex> --var RELAY_URL:ws://localhost:8799
   ```

4. Run the suite. `--script` prints one JSON line per check:

   ```sh
   ./target/release/relay-tester --script ws://localhost:8799 <first nsec> <second nsec>
   ```

   Without `--script` it prints every message it sends and receives, which shows why a check failed.

5. Stop `wrangler dev` and delete the state directory.

## Reading the result

The recorded run gave 28 passes, 49 failures and 4 checks skipped, out of 81. The failures fall into these groups,
each expected:

- **Reads without AUTH.** relay-tester reads in its first stage without authenticating, and in its second stage it
  authenticates only when its connection still holds an unanswered challenge. The last check of the first stage
  leaves a refused AUTH (a stale `created_at`), so the second stage never authenticates, and every `REQ` is answered
  `CLOSED` with `auth-required:` (RD-1). The read checks (EOSE, finding by id, author, kind and tags, ordering,
  limits, `since` and `until`, replaceable and addressable lookups) and the checks that read to confirm a write (such
  as "Accepts metadata" and "Delete by a-tag deletes older but not newer") fail for this reason, not for what they
  test. The read path is covered by `packages/relay/src/protocol.ws.test.ts` and `events.ws.test.ts`.
- **Writes from the public.** The second key is not on the allowlist, so its events are `blocked:` (WR-1), and its
  AUTH is `restricted:`.
- **Policies of this relay.** An older replaceable or addressable version is accepted and kept as history (ST-4);
  `created_at` more than 900 seconds ahead is refused (EV-4); a negative or non-integer `created_at` and an empty tag
  are refused (EV-3); an id computed over escapes as the client wrote them (`\u0000`, `\/`), rather than over the
  NIP-01 or the `JSON.stringify` serialization, does not match (EV-2); raw control characters inside a JSON string are
  not valid JSON and get a `NOTICE`.
- **NIPs not implemented.** NIP-04, 26, 29, 45, 50, 59, 65, 94 and 96 are not claimed in the NIP-11 document.

The checks that pass and mean something here are the AUTH verification checks (kind, relay, challenge and time), the
signature and id checks, `OK` after `EVENT`, the NIP-01 escapes, past `created_at` values, and refusing an event
whose address was deleted. Some deletion checks pass only because the event they look for cannot be read. A change
that turns a meaningful pass into a failure, or a failure outside the groups above, needs a look.
