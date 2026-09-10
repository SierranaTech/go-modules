# Engineering plan: repo skeleton, the `obs` submodule, first migration

Covers phase 1 of the rollout in `docs/` research: stand up `go-modules`, ship
the `obs` submodule, migrate one reference consumer. Later packages (`config`,
`log`, `httpx`, `pushover`, `postmark`) and the stiwdiohouse batch are out of
scope here and get their own plan.

## Status

- repo skeleton and the `obs` module are built and green locally: `go vet`,
  `golangci-lint`, `go test -race`, coverage 90.8 percent. Not yet a GitHub
  repo, no `local.repos` entry, nothing tagged.
- the root module and `go.work` are deferred: with one module they are empty
  ceremony. They arrive with the second module (`config`), in phase 3.
- two small build-time decisions, both behaviour-preserving:
  - `SendDefaultPII: false` is dropped, not carried. It is deprecated in
    sentry-go v0.48 and `false` is already the default. A comment records the
    intent. Moving to the modern `DataCollection` option is a later follow-up.
  - the test seam mocks with `sentry.MockTransport` (the name in v0.48), fed
    through `initWith`.

## Ponytail pass

Smaller version considered: skip the repo, add a `go.work` across the existing
clones and a `replace` in each consumer pointing at one chosen service's
`observability/` package. Rejected: no versioning, no independent CI, and it
makes one service's `internal/` load-bearing for the fleet. The repo is the
actual ask.

What we are not doing in phase 1: no `release` automation (manual tags), no
`config`/`log`/`httpx` yet, no stiwdiohouse migrations (they wait on the App
change), no `capture.go` behaviour changes (`log.Print` stays, not slog).

## Correction to the research doc

There are no existing tests for the `observability` package in any consumer.
`obs` needs tests written from scratch. The earlier note about "moving postal's
tests" was wrong.

## What `obs` is

A near-verbatim lift of the `observability` package that eleven repos carry.
Three source concerns, one Go package `obs`, import path
`github.com/SierranaTech/go-modules/obs`, its own `go.mod` requiring
`github.com/getsentry/sentry-go`.

Behaviour is preserved. The only deliberate changes:

- the `serviceName` constant becomes a required config field.
- the scrub lists become a built-in default plus caller-supplied additions. A
  caller can grow the lists, never shrink them.
- a stale copy-paste comment referencing "the stiwdiohouse monorepo" is dropped.

### API surface

```go
package obs

type Config struct {
    Service           string   // required; sets the "service" Sentry tag
    ExtraScrubHeaders []string // appended to the default scrubbed headers
    ExtraScrubFields  []string // appended to the default scrubbed form fields
}

// Init configures the global Sentry hub from the environment
// (SENTRY_DSN, SENTRY_ENVIRONMENT, SENTRY_RELEASE, SENTRY_TRACES_SAMPLE_RATE),
// exactly as the copied package did. No-op when SENTRY_DSN is empty.
// Returns a flush func the caller defers. Panics if Config.Service is empty.
func Init(cfg Config) func()

// internal seam for tests: builds the same sentry.ClientOptions and lets a
// test pass a sentry.TransportMock so no assertion path touches the network.
// Init is a thin wrapper: func Init(cfg Config) func() { return initWith(cfg, nil) }
func initWith(cfg Config, transport sentry.Transport) func()

// Capture logs err and forwards it to Sentry via the context hub if present.
func Capture(ctx context.Context, msg string, err error, fields ...any)

// ServerError captures err and writes a 500 with body {"error": msg}.
func ServerError(w http.ResponseWriter, r *http.Request, msg string, err error, fields ...any)

// Revision returns the binary's vcs.revision, or "" when unavailable.
// Exposed because services reimplement this: postal's cmd/postal/main.go
// has its own buildVersion() doing the same debug.ReadBuildInfo lookup.
func Revision() string
```

Default scrub lists, unchanged from the copies:

- headers: `Cookie`, `Set-Cookie`, `Authorization`, `X-Stripe-Signature`
- form fields: `password`, `current_password`, `new_password`,
  `confirm_password`, `token`, `session_token`

### Files

```
obs/
  go.mod          module github.com/SierranaTech/go-modules/obs, go 1.26.0
  go.sum
  doc.go          package comment
  sentry.go       Config, Init, initWith, scrubber (beforeSend, scrubFormBody)
  capture.go      Capture, ServerError, logFields and its helpers
  buildinfo.go    Revision (was the unexported readVCSRevision)
  obs_test.go
```

Built. The `serviceName` const is gone, the scrub lists are `defaultScrub*`
package vars, and `initWith(cfg, transport)` is the unexported seam Init wraps.

### Tests (deterministic, no network)

`scrubEvent` and `scrubFormBody` are pure and take the load:

- form body `a=1&password=x&c=3` becomes `a=1&password=[scrubbed]&c=3`
- field match is case-insensitive (`Password` is scrubbed)
- a body with no `=` is returned unchanged
- `Authorization` and `Cookie` headers on a `sentry.Event` become `[scrubbed]`;
  a non-listed header is untouched
- `ExtraScrubFields: ["otp"]` scrubs `otp` and still scrubs `password`
- `ExtraScrubHeaders` behaves the same for headers

`Init`:

- empty `SENTRY_DSN` returns a non-nil no-op flush
- empty `Config.Service` panics
- with `SENTRY_DSN` set and a `sentry.MockTransport` injected through
  `initWith`, a subsequently captured event carries the `service` tag. No
  network: the mock transport is the seam, asserted on its recorded events.

`Capture` with a context carrying a hub built on a `sentry.MockTransport`
records one event on that hub. `ServerError` writes status 500, a
`{"error": msg}\n` body and `Content-Type: application/json`.

`TestInitSetsServiceTag` is the only test that binds a client on the global
Sentry hub. It unbinds in `t.Cleanup` so nothing leaks to a later test, and the
suite passes under `go test -shuffle=on`.

Achieved coverage: the pure scrub functions at 100 percent, package overall
90.8.

### CI

`.github/workflows/ci.yml`: a matrix with one `include` entry per module
directory (just `obs` now). Each job runs `setup` with
`go-mod-directory: <module>` then `go-suite` with `working-directory` and
`badge-prefix` set to the module name. `run-report` is true only on push to
`main`. No `build`, `retag`, or Docker jobs; this repo produces no image.

When the root module is added, its matrix entry passes `working-directory: "."`,
never `""`: `go-suite`'s `default: "."` only applies when the input is omitted,
and an explicit empty string breaks the composite's inner steps.

`mise.toml` drives every module from a space-separated `MODULES` env var, so
adding a submodule dir there updates `tidy`, `fmt`, `lint` and `test` at once.
`.pre-commit-config.yaml` calls the mise tasks. `renovate.json` extends the
org's `common-go` preset.

## iac changes (separate PR, auth review)

In `iac/environments/aws`:

Drafted on branch `feat/go-modules-private-module-access` in `iac`, conservative
form, not for apply:

1. `_locals.tf`: `"go-modules" = { ci = true }` added. No `ecr`.
2. `private-modules.tf`: `repositories` widened to the phase-1 consumers
   (`postal`, `chronix`, `octappus`, `zakarix`, `vidistet`, `kairos`,
   `copywrite`) on top of the three stiwdiohouse entries. `branch_patterns`
   unchanged. A header comment lists what was deliberately left out.

Left for the security review to decide, all flagged in the file:

- rename `name` from `stiwdiohouse-modules` to an org-neutral slug. That
  recreates the IAM role and the SSM parameter (the App PEM re-uploaded) and
  needs the composite's `aws-role` / `parameter-name` defaults changed in
  lockstep. Deferred to its own change.
- trust every Go consumer now, or grow the list per phase.
- `:pull_request` trust (`allow_pull_request` defaults true): confirm PR builds
  on these repos should mint the token.
- confirm `postal`'s GitHub org matches its `local.repos` key. Its go.mod says
  `github.com/Sierra1011/postal`, the same stale-path pattern as `chronix`. If
  the repo really lives outside `SierranaTech`, `module.github_repo["postal"]`
  will not resolve at plan time. A 30-second check for whoever runs the plan.

Post-apply, operator: install the existing App on `go-modules` with
`Contents: Read`, alongside `stiwdiohouse-contracts`.

Plan the tofu diff by resource and confirm the prod plan for unrelated stacks
shows no changes. This widens an OIDC trust policy: it goes through
`/security-review` before apply.

## Reference migration: `postal`

Chosen over `chronix` because the local `chronix` checkout is on an old module
path (`chronix.sierra1011.github.com`, go 1.25) and would conflate a layout
upgrade with this change. Refresh every consumer's `main` before touching it;
the local clones are snapshots.

`postal` migration PR:

- `go get github.com/SierranaTech/go-modules/obs@v0.1.0`
- delete `internal/observability/`
- replace `observability.Init()` with
  `obs.Init(obs.Config{Service: "postal"})`, keep the `defer ...()` shape
- replace `observability.Capture` / `observability.ServerError` call sites with
  `obs.` equivalents (import rename only)
- `.github/workflows/ci.yml`: add `go-modules` to the `repositories` input of
  the `private-modules-token` step, or add the step if postal does not fetch a
  private module yet
- `go mod tidy`, then `mise run tidy fmt lint test`

Optional in the same PR, only if it stays a one-liner: replace postal's
`cmd/postal/main.go` `buildVersion()` with `obs.Revision()` and delete the
former. If it is not clean, leave it for a follow-up; do not grow this PR.

Diff is a package deletion plus an import rename. Reviewable by eye.

- covered by unit tests: the `obs` package tests above. postal keeps its own
  suite green; no postal behaviour changes.
- after deploy: trigger a deliberate error in postal (malformed inbound
  webhook) and confirm it lands in Sentry tagged `service:postal` with the
  release set to the running revision.
- rollout: no flag. Revert is `git revert` of the one PR; the old package
  comes back with it.

## Remaining consumers, after the reference migration

Straightforward, one PR each, same shape as postal:
`chronix` (also bump it to the standard module path), `octappus`, `zakarix`,
`vidistet`.

- `vidistet`: pass `ExtraScrubFields: ["pushover_user_key", "session_secret",
  "github_client_secret"]`. It regains `password` and `token` scrubbing that its
  local copy had dropped, and gains `capture.go` helpers it never had. Confirm
  nothing depended on the missing `X-Stripe-Signature` entry (it has no Stripe).
- `kairos`: its variant logs init failures through `slog.Warn`. Moving to `obs`
  means one startup line goes back to `log.Printf`. Note it in the PR; not worth
  a config knob.
- `copywrite`: its collapsed 31-line `observability.go` needs reading first.
  Migration likely adds scrubbing it currently lacks, which is a fix, but check
  it does not call a helper `obs` does not provide.

The six stiwdiohouse services migrate as a batch once the App covers them, so
producer and consumer CI can fetch `go-modules` in the same window. That batch
is part of the phase 5 stiwdiohouse plan, not this one.

## Risks

- Stale local clones. Mitigated: refresh `main` per consumer before its PR.
- Module-path drift (`chronix`). Mitigated: fold the path fix into chronix's
  migration, do not block the reference migration on it.
- The auth change is the real risk surface. It is isolated in its own iac PR
  with a security review and does not gate writing the `obs` code.
- `sentry-go` version skew: consumers pin `v0.46.2` and similar. `obs` picks one
  recent `v0.x` and consumers move to it on migration. Note the version in each
  PR.

## Sequence

1. iac PR: `local.repos` entry, instance rename, trust widening. Security
   review. Apply. Operator App install and SSM steps. Not started.
2. `go-modules` repo: skeleton, `obs` package, tests, CI green. Done locally.
   Remaining: create the GitHub repo, push, confirm CI is green on the runners,
   tag `obs/v0.1.0`.
3. `postal` migration PR. Merge, deploy, run the post-deploy check.
4. `chronix`, `octappus`, `zakarix`, `vidistet`, `kairos`, `copywrite`, one PR
   each.
5. Hand off to the phase 5 plan for stiwdiohouse and the tier-3 packages.

Steps 2 (push), 3 and 4 are all ship-gated and blocked on step 1's review.
