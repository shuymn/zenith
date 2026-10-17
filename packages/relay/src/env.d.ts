declare namespace Cloudflare {
  interface Env {
    VAULT: DurableObjectNamespace<import("./vault.ts").Vault>;
    /** The owner's public key, 64 lowercase hex characters (`parseVaultConfig`). */
    OWNER_PUBKEY: string;
    /** The ws or wss URL clients connect to (`parseRelayConfig`). */
    RELAY_URL: string;
  }
}

interface Env extends Cloudflare.Env {}
