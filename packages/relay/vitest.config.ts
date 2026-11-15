import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

/** WebSocket tests talk to the Vault DO through the Worker; see the websocket project below. */
const WEBSOCKET_TESTS = "src/**/*.ws.test.ts";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        // Test values only: the owner is publicKeyOf(testSecretKey("owner")) from src/test-support.ts.
        bindings: {
          OWNER_PUBKEY: "4c97e239cfb7d131a9c3bf3473ff823d27868353ed740c54f8f7d01f3e5dd79c",
          RELAY_URL: "wss://relay.example/",
        },
      },
    }),
  ],
  test: {
    projects: [
      {
        extends: true,
        test: {
          name: "storage",
          include: ["src/**/*.test.ts"],
          exclude: [WEBSOCKET_TESTS],
          sequence: { groupOrder: 0 },
          // The files run in parallel. On the CI runner, backup.test.ts and store.test.ts take 2–4 s each, and execution
          // delays occasionally pushed their property tests, and once a small R2 test, past the default 5 s; a rerun of
          // the same commit passed. Locally the property tests take under 1 s.
          testTimeout: 30_000,
        },
      },
      // The Workers Vitest integration does not support Durable Object WebSockets with per-file storage isolation;
      // its known issues page gives `--max-workers=1 --no-isolate` as the workaround. These files therefore share one
      // storage and run one at a time, and each test leaves no connection open.
      {
        extends: true,
        test: {
          name: "websocket",
          include: [WEBSOCKET_TESTS],
          isolate: false,
          maxWorkers: 1,
          sequence: { groupOrder: 1 },
        },
      },
    ],
  },
});
