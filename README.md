# zenith

Zenith Vault is a private, single-user Nostr relay built on Cloudflare Workers.

## Development

Tool versions come from `mise.toml`, with exact versions pinned in `mise.lock`.

```sh
mise install                # Node.js, pnpm and the workflow linters
pnpm install                # dependencies
pnpm exec lefthook install  # git hooks (optional)
pnpm run lint               # oxlint with type-aware rules
pnpm run fmt                # oxfmt check (pnpm run fmt:fix to apply)
pnpm run typecheck          # TypeScript
pnpm run test               # Vitest
```
