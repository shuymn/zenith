# zenith

Zenith Vault is a private, single-user Nostr relay built on Cloudflare Workers.

Security invariants and the threat model: [docs/threat-model.md](docs/threat-model.md).
Library choices and the patterns every package follows: [docs/decisions.md](docs/decisions.md).

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

The GitHub repository settings are declared in `.github/infra.yaml`; review
them with `gh infra plan` and apply them with `gh infra apply`.
