# Multi-module repo, split by dependency footprint

## Context

We are pooling code that ~20 Go services copy-paste today. The largest
case, the `observability` package, is byte-identical across eleven repos
and has already drifted in one of them. A shared repo fixes that, but the
packaging choice is hard to undo: it sets the import paths and the
release process, and changing it later forces every consumer to rewrite
imports and re-pin.

## Decision

One repo, `github.com/SierranaTech/go-modules`, as a multi-module repo:

- a **root module** holding every stdlib-only package: `config`, `log`,
  `httpx`, `pushover`, `postmark`. Tagged `vX.Y.Z`.
- a **submodule per heavy dependency**: `obs` (`getsentry/sentry-go`)
  first, later `pg` (`jackc/pgx`) and `operator-bootstrap`
  (`sigs.k8s.io/controller-runtime`). Each has its own `go.mod` and tag
  namespace (`obs/vX.Y.Z`).
- submodules do not import each other or the root module. A consumer that
  needs two of them wires both itself.
- a committed `go.work` at the root for in-repo development; consumers
  ignore it and pin tags.
- releases are manual (`git tag obs/v0.2.0 && git push --tags`), matching
  `stiwdiohouse-contracts`. The `SierranaTech/actions` `release`
  composite, which understands tag prefixes, is the fallback if tagging
  becomes toil.

## Considered options

- **Single module, subpackages** (what `stiwdiohouse-contracts` does).
  Simplest to release, but every consumer of any package pulls
  `sentry-go`, and later `pgx` and `controller-runtime`, into its build
  graph. Rejected: the whole reason to group this code is that services
  have different dependency appetites.
- **One module per package.** Maximum isolation, but five-plus release
  flows and tag namespaces for code that is mostly zero-dependency and
  changes rarely. Rejected as ceremony without payoff: stdlib-only
  packages have nothing to isolate from each other.

## Consequences

- CI is a matrix over module directories. `go-suite` already supports
  this via its `working-directory` and `badge-prefix` inputs.
- A change spanning the root module and a submodule is two tags and two
  PRs in consumers. Acceptable: submodules are meant to be independent.
- `go.work` must list new submodules as they are added, or in-repo builds
  miss them.
