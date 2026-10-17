/**
 * The relay's configuration, read from the Worker's variables: the owner (`OWNER_PUBKEY`) and the relay URL
 * (`RELAY_URL`), the URL clients connect to and name in the `relay` tag of an AUTH event (RD-2).
 */
import { parseVaultConfig, type ConfigError, type VaultConfig } from "./allowlist.ts";

export type RelayConfig = {
  readonly vault: VaultConfig;
  /** A ws or wss URL; verifyAuthEvent compares its host with the AUTH event's `relay` tag. */
  readonly relayUrl: string;
  /** The path of {@link relayUrl}: the one path that accepts WebSocket upgrades and serves NIP-11. */
  readonly path: string;
};

export const RELAY_CONFIG_ERRORS = ["missing-relay-url", "bad-relay-url"] as const;
export type RelayConfigError = ConfigError | (typeof RELAY_CONFIG_ERRORS)[number];
export type RelayConfigResult = { ok: true; config: RelayConfig } | { ok: false; error: RelayConfigError };

export function parseRelayConfig(vars: {
  readonly OWNER_PUBKEY?: unknown;
  readonly RELAY_URL?: unknown;
}): RelayConfigResult {
  const vault = parseVaultConfig(vars);
  if (!vault.ok) return fail(vault.error);
  const relayUrl = vars.RELAY_URL;
  if (relayUrl === undefined || relayUrl === "") return fail("missing-relay-url");
  if (typeof relayUrl !== "string" || !URL.canParse(relayUrl)) return fail("bad-relay-url");
  const url = new URL(relayUrl);
  if ((url.protocol !== "ws:" && url.protocol !== "wss:") || url.username !== "" || url.password !== "") {
    return fail("bad-relay-url");
  }
  return { ok: true, config: { vault: vault.config, relayUrl, path: url.pathname } };
}

function fail(error: RelayConfigError): RelayConfigResult {
  return { ok: false, error };
}
