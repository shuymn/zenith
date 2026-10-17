import type { VerifiedEvent } from "./event.ts";

/**
 * The canonical JSON of a verified event (ST-7): the seven verified fields in a fixed order,
 * rebuilt from the verified values rather than copied from the received text. It is not used for the id.
 */
export function canonicalEventJson(event: VerifiedEvent): string {
  const { id, pubkey, created_at, kind, tags, content, sig } = event;
  return JSON.stringify({ id, pubkey, created_at, kind, tags, content, sig });
}
