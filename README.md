# go-modules

Shared Go code for SierranaTech services: the wiring that every `ci` + `ecr`
Go service was copying by hand. One repo, one module per third-party dependency
footprint.

See `CONTEXT.md` for the vocabulary and `docs/adr/` for the packaging
decisions.

## Modules

| Import path | Tags | Depends on | Purpose |
|---|---|---|---|
| `github.com/SierranaTech/go-modules` | `vX.Y.Z` | stdlib only | Root module; see below |
| `github.com/SierranaTech/go-modules/obs` | `obs/vX.Y.Z` | `getsentry/sentry-go` | Sentry init with request scrubbing, plus `Capture` / `ServerError` helpers and `Streak` for polling loops |

Root module packages:

| Import path | Purpose |
|---|---|
| `github.com/SierranaTech/go-modules/githubauth` | Deprecated: GitHub OAuth sign-in, removed in `v1.0.0` once every consumer has moved to `oidcauth` |
| `github.com/SierranaTech/go-modules/oidcauth` | OpenID Connect sign-in (any issuer, Authelia first) and session handling, optionally restricted to members of given groups |

More stdlib-only packages (`config`, `log`, `httpx`, `pushover`, `postmark`)
land in the root module as they're needed. Heavy-dependency packages (`pg`,
`operator-bootstrap`) each get their own submodule.

## Using a module

```go
import "github.com/SierranaTech/go-modules/obs"

func main() {
	defer obs.Init(obs.Config{Service: "widget"})()
	// ...
}
```

Pin a tag with `go get github.com/SierranaTech/go-modules/obs@obs/v0.1.0`, or
`go get github.com/SierranaTech/go-modules@v0.1.0` for a root module package
such as `githubauth`. For local development against an unreleased change, add
a `replace`:

```
replace github.com/SierranaTech/go-modules/obs => ../go-modules/obs
replace github.com/SierranaTech/go-modules => ../go-modules
```

## Development

```
mise run test
```

<!-- generated:quality-obs:start -->

[![obs coverage](.github/badges/coverage-obs.svg)](obs/.artifacts/coverage-summary.txt)
obs coverage: **90.2%**

<!-- generated:quality-obs:end -->
