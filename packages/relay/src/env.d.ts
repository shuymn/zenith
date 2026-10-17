declare namespace Cloudflare {
  interface Env {
    VAULT: DurableObjectNamespace<import("./index.ts").Vault>;
  }
}

interface Env extends Cloudflare.Env {}
