# go-modules

Shared Go code for SierranaTech services: the wiring that every `ci` + `ecr`
Go service was copying by hand. One repo, one module per third-party dependency
footprint.

See `CONTEXT.md` for the vocabulary, `docs/adr/` for the packaging decisions,
and `docs/PLAN-phase-1-obs.md` for what is being rolled out now.

## Modules

| Import path | Tags | Depends on | Purpose |
|---|---|---|---|
| `github.com/SierranaTech/go-modules/obs` | `obs/vX.Y.Z` | `getsentry/sentry-go` | Sentry init with request scrubbing, plus `Capture` / `ServerError` helpers |

Stdlib-only packages (`config`, `log`, `httpx`, `pushover`, `postmark`) land in
a root module in a later phase. Further heavy-dependency packages (`pg`,
`operator-bootstrap`) each get their own submodule.

## Using a module

```go
import "github.com/SierranaTech/go-modules/obs"

func main() {
	defer obs.Init(obs.Config{Service: "widget"})()
	// ...
}
```

Pin a tag with `go get github.com/SierranaTech/go-modules/obs@obs/v0.1.0`. For
local development against an unreleased change, add a `replace`:

```
replace github.com/SierranaTech/go-modules/obs => ../go-modules/obs
```

CI fetches this repo through the org's private-module App; add `go-modules` to
the `repositories` input of the `private-modules-token` step.

## Development

```
mise run test
```

<!-- generated:quality-obs:start -->

[![obs coverage](.github/badges/coverage-obs.svg)](obs/.artifacts/coverage-summary.txt)
obs coverage: **90.2%**

<!-- generated:quality-obs:end -->
