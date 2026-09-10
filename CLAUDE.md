# go-modules

Shared Go modules for SierranaTech services. Read `CONTEXT.md` for vocabulary,
`docs/adr/` for decisions, `docs/PLAN-phase-1-obs.md` for the current plan.

## Layout

Multi-module repo, one module per dependency footprint:

- `obs/` — Sentry wiring. Depends on `getsentry/sentry-go`. Tags `obs/vX.Y.Z`.

Stdlib-only packages (`config`, `log`, `httpx`, `pushover`, `postmark`) will
live in a root module added in a later phase. A `go.work` gets added with the
second module. Heavy-dependency packages (`pg`, `operator-bootstrap`) each get
their own submodule.

## Rules

- submodules do not import each other or a root module.
- packages here are behaviour-preserving lifts from consumers. The only
  deliberate changes are the ones written down in the ADR or the plan.
- releases are manual: `git tag obs/vX.Y.Z && git push --tags`.
- SemVer per module. While a module is `v0`, a breaking change bumps the minor.
- tests are deterministic: no network, mock the Sentry transport at the seam
  (`initWith`), inject time.
