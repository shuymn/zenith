export const KIND_CLASSES = ["regular", "replaceable", "ephemeral", "addressable", "unknown"] as const;
export type KindClass = (typeof KIND_CLASSES)[number];

/**
 * Classifies an event kind by its storage semantics as defined in NIP-01.
 * The caller decides how to store events of an "unknown" kind.
 */
export function classifyKind(kind: number): KindClass {
  if ((kind >= 1000 && kind < 10000) || (kind >= 4 && kind < 45) || kind === 1 || kind === 2) {
    return "regular";
  }
  if ((kind >= 10000 && kind < 20000) || kind === 0 || kind === 3) {
    return "replaceable";
  }
  if (kind >= 20000 && kind < 30000) {
    return "ephemeral";
  }
  if (kind >= 30000 && kind < 40000) {
    return "addressable";
  }
  return "unknown";
}
