declare namespace Cloudflare {
  interface Env {
    VAULT: DurableObjectNamespace<import("./vault.ts").Vault>;
    /** The backup bucket (DATA-5): a separate R2 bucket with a 30-day bucket lock. */
    BACKUPS: R2Bucket;
    /** The owner's public key, 64 lowercase hex characters (`parseVaultConfig`). */
    OWNER_PUBKEY: string;
    /** The ws or wss URL clients connect to (`parseRelayConfig`). */
    RELAY_URL: string;
  }
}

interface Env extends Cloudflare.Env {}
