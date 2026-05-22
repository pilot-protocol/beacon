# Contributing

Thanks for your interest in contributing to `beacon` — Pilot Protocol beacon — STUN/NAT-punch/relay service co-deployed with rendezvous at the network edge.

## Quick start

```bash
git clone https://github.com/pilot-protocol/beacon.git
cd beacon
go test -race ./...
```

## Pull requests

1. Open an issue first for non-trivial changes so design can be discussed.
2. Branch off `main`; keep changes focused and self-contained.
3. Tests are required for new behavior; passing CI is required to merge.
4. Coverage should not regress (Codecov reports per-PR delta).
5. Conventional commit style is preferred (`feat:`, `fix:`, `docs:`, `chore:`, …) but not enforced.

## Code of conduct

Be respectful and constructive. Project maintainers will moderate.

## License

By contributing you agree your contributions will be released under the
project's license (AGPL-3.0-or-later — see `LICENSE`).
