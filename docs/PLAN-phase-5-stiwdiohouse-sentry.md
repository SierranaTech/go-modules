# Engineering plan: Sentry capture coverage and alerting for stiwdiohouse

Phase 5 of the observability rollout. The stiwdiohouse services already import
`obs` (phase 1 migrated them to `obs/v0.1.0`). This plan closes the gaps that
stop errors reaching Sentry, then puts one alert on the resulting stream.

Written 2026-10-03 without a grill-with-docs session: the work was started
unattended, so the design questions below were settled by survey rather than
by discussion. Each one names the evidence it rests on.

## Status

As of 2026-10-03. Nothing is merged or deployed.

- capture fixes, one PR per repo, all open with CI green:
  SierranaTech/homelab#883, stiwdiohouse-schema#29, stiwdiohouse-booking#34,
  stiwdiohouse-payments#71, stiwdiohouse-community#25,
  stiwdiohouse-gateway#40, stiwdiohouse-notifications#27,
  stiwdiohouse-video#35.
- silent-500 sweep, stacked on each service's capture PR: booking#35,
  community#26, gateway#41, notifications#28, payments#72, video#36. 83
  sites moved to `obs.ServerError`; 7 left alone (already captured, or no
  error in scope).
- ops doc correction: SierranaTech/stiwdiohouse#80.
- Sentry alert rule: not created. The Sentry API returned 403 for alert
  writes with the token available. Tracked in SierranaTech/stiwdiohouse#81
  with the exact configuration.
- follow-ups filed: go-modules#14 (`obs.Recoverer`, `obs.RunMonitored`, Go
  directive policy), stiwdiohouse#82 (browser SDK decision), stiwdiohouse#83
  (request ids, proxy errors, unrecovered goroutines).
- not verified: whether deployed pods currently initialise Sentry at all, and
  whether the four services without git in their builder report an empty
  release. Production log reads were not available during this work; the
  post-deploy checks below settle both.
- worktrees from `origin/main` live under
  `/var/home/simeon/git/worktrees/sentry/`, one per repo.

## What the survey found

Sentry received one error event from the whole platform in 90 days
(`STIWDIOHOUSE-BOOKING-1`, 2026-10-02, a 400-class bug already fixed). The
operator project received 682 in the same window. Either stiwdiohouse is
spotless or the pipe is blocked. The code says blocked:

- handler panics never reach Sentry. Every service wraps the chi router in
  `sentryhttp` from the outside and runs `chimiddleware.Recoverer` inside it.
  Recoverer recovers, logs and writes a 500 without re-panicking, so the
  outer sentryhttp handler never sees the panic. Its only live job is putting
  a per-request hub on the context for `obs.Capture`.
- the two CronJobs cannot report. The operator gives a CronJob the service's
  ConfigMap and the `<svc>-secrets` Secret via `envFrom`, but `SENTRY_DSN` is
  an explicit `service.env` entry that CronJobs do not inherit. The Secret's
  key arrives as a lowercase `sentry_dsn` variable, which `obs.Init` does not
  read. Both cron code paths (booking `generate-sessions`, payments
  `reconcile-capacity`) also fail through `log.Fatalf`, which skips both the
  capture and the deferred flush.
- the schema migrator captures then calls `os.Exit(1)` before the deferred
  flush runs. sentry-go's default transport is asynchronous, so the event is
  usually lost.
- release stamping is unverified for four services. `obs.Init` takes the
  release from `SENTRY_RELEASE` (set nowhere) or `vcs.revision`. Go stamps
  `vcs.revision` only when `git` is on the build image; community, gateway,
  notifications and schema build on `golang:alpine` without it. CI creates a
  Sentry release per commit SHA, so events from those services most likely
  land with no release and never match it.
- many 500s are silent: local `writeError(w, 500, ...)` with no capture.
  booking 8, community 19, gateway 7, notifications 33 (log only), payments 7,
  video 11. These are the next PR per service, not this one.
- every service pins `obs/v0.1.0`. `obs/v0.3.0` turns `Capture` fields into
  Sentry tags, adds `CaptureFingerprint` and breadcrumbs, and fixes
  `EnableTracing`. Gateway and video already pass `user_id` as a field and
  get nothing for it on v0.1.0.
- alerting today is Sentry's per-project default: "high priority issues",
  email to issue owners, fall through to all active members. Email is the
  only notification integration installed. There are no metric monitors, no
  cron monitors and no org-level rule.
- `stiwdiohouse-web` (Hugo) and `stiwdiohouse-admin` (Alpine.js) are static
  sites behind nginx with no Sentry SDK. Their manifests set
  `SENTRY_ENVIRONMENT` for nothing. There is no Sentry project for admin.
- six service `CLAUDE.md` files describe an `internal/observability` package
  that no longer exists and the retired SSM path `/apps/stiwdiohouse-<svc>/`.

## Decisions

### Fix the panic path in each service, not in `obs`

The clean fix is an `obs.Recoverer` middleware with one test. It is blocked:
`go-modules` main now declares `go 1.27.1` (Renovate PR #1, not a design
choice) and every stiwdiohouse service is on `go 1.26.3` with a
`golang:1.26.5-alpine` builder. Tagging `obs/v0.4.0` from main would force
the fleet onto Go 1.27 and the exact-pin toolchain dance the phase-1 plan
documents. A maintenance branch at Go 1.26 for one helper is not worth it.

So each service reorders two lines. Recoverer stays outermost. `sentryhttp`
moves inside the router with `Repanic: true`, so a panic is captured first
and re-raised for Recoverer to turn into a 500. The outer `.Handle(r)` wrapper
goes. The trap to avoid: `Repanic: false` with no Recoverer turns every panic
into an empty 200, because sentryhttp recovers and returns with nothing
written.

The two lines live in a `usePanicCapture(chi.Router)` function in `main` so
one test can drive a panicking handler through the real middleware order and
assert both the 500 and the captured event. `obs.Recoverer` stays the named
upgrade path (follow-up issue in `go-modules`).

### Cron paths: capture, flush, exit, plus a Sentry cron monitor

`log.Fatalf` becomes `obs.Capture`, an explicit `flush()`, then `os.Exit(1)`.
The flush returned by `obs.Init` is kept in a variable for that purpose.

Each cron run also reports a Sentry check-in (`in_progress` on start, `ok` or
`error` on finish) with a `MonitorConfig` carrying the same crontab and
timezone as the homelab manifest. sentry-go upserts the monitor from that
config on first check-in, so nothing is created by hand. A missed or failed
nightly `generate-sessions` run becomes a Sentry issue, which is the alert
that matters most for these jobs. The schedule is duplicated between manifest
and code; a comment in each names the pairing.

`runMonitored(hub, slug, schedule, timezone, fn)` lives in each service's
`main` package with a `MockTransport` test. Same upgrade path: move to `obs`
when a Go 1.26 tag is possible.

Monitor slugs and schedules:

- `booking-generate-sessions`: `0 2 * * *`, `Europe/London`, margin 30 min,
  max runtime 30 min
- `payments-reconcile-capacity`: `*/5 * * * *`, `Europe/London`, margin 5
  min, max runtime 5 min. The job no-ops when not due; a no-op still
  checks in `ok`, which is the point: the heartbeat itself is monitored.

### Release stamping: install git in the four builders

`apk add --no-cache git` in the community, gateway, notifications and schema
Dockerfiles, matching booking, payments and video. No `SENTRY_RELEASE`
plumbing in CI or the operator: `vcs.revision` already equals the SHA the
CI release is named after. This remains an inference from source; the
post-deploy check below settles it.

### One org-level alert, email only

Create one Sentry Alert connected to the seven stiwdiohouse issue streams
(booking, community, gateway, notifications, payments, schema, video):

- name: `stiwdiohouse: new or regressed issue (production)`
- triggers (`any-short`): `first_seen_event`, `regression_event`
- action filter (`all`): `event_attribute` `environment` `eq` `production`
- action: `email`, `targetType` `user`, `targetIdentifier` `4592182`
- frequency: 30 minutes
- owner: `user:4592182`

The seven default "high priority issues" rules stay. They already email
active members and cover escalation; the new rule adds first occurrence and
regression at any priority, production only, so staging noise does not
page. Metric monitors are deliberately skipped: a count threshold on a
near-zero baseline either never fires or is noise. Revisit once the stream
has a week of real traffic. The legacy `stiwdiohouse` project is left out.

### Not in this round

- browser SDK for web and admin. A third-party script on a public site that
  already runs Plausible, against an org stance of avoiding JavaScript, is a
  product decision. Follow-up issue with the loader-script shape, and a note
  that admin has no Sentry project.
- request-ID propagation and tagging. Only video runs `RequestID` and nobody
  tags it. Follow-up issue.
- a non-email channel. Nothing beyond email is installed in the org.

## Changes per repo

### Six HTTP services (booking, community, gateway, notifications, payments, video)

- `go.mod`: `github.com/SierranaTech/go-modules/obs` to `v0.3.0`
- `cmd/server/main.go`: `usePanicCapture(r)` replaces the Recoverer line and
  the outer `sentryhttp` wrapper; `srv.Handler` is `r`
- `cmd/server/main_test.go`: `TestPanicIsCapturedAndReturns500`
- `CLAUDE.md`: Observability section names `obs.Init` and the canonical SSM
  path `/apps/stiwdiohouse/<svc>/sentry/dsn`
- community, gateway, notifications `Dockerfile`: `apk add --no-cache git`

booking and payments additionally:

- `cmd/server/main.go`: cron branch wrapped in `runMonitored`; failures
  captured, flushed, then `os.Exit(1)`
- `cmd/server/main_test.go`: `TestRunMonitoredReportsCheckIns`

### schema

- `cmd/migrator/main.go`: keep the flush func, call it before `os.Exit(1)`
- `Dockerfile`: `apk add --no-cache git`
- `go.mod`: obs `v0.3.0`

### homelab

- `manifests/stiwdiohouse/base/booking/microservice.yaml` and
  `.../payments/microservice.yaml`: add `SENTRY_DSN` `secretKeyRef` to the
  CronJob `env` list, same Secret and key as the Deployment. Must land before
  the service PRs deploy, or the check-ins are a no-op (no client, nil ID).

### go-modules

- this document. No code change.

## Tests

Deterministic, no network, `sentry.MockTransport` bound to a hub built in
the test:

- `TestPanicIsCapturedAndReturns500`: chi router with `usePanicCapture`, a
  handler that panics, `httptest` request. Asserts status 500 and exactly one
  event on the mock transport whose exception value is the panic message.
- `TestRunMonitoredReportsCheckIns`: `fn` returns an error. Asserts two
  check-ins on the transport, `in_progress` then `error`, same monitor slug,
  and that the error is returned to the caller. A second case with `fn`
  returning nil asserts `ok`.
- `obs` itself is unchanged; its suite already covers `Init`, `Capture`,
  `ServerError`.

Every service's existing suite stays green; `go vet` and `golangci-lint`
clean.

## Post-deploy checks

Per service, after the image rolls:

- pod log carries `sentry initialised service=<svc> environment=production
  release=<sha>`. Run `kubectl --context production -n stiwdiohouse logs
  deploy/<svc> | grep sentry`. The release must be the deployed commit, which
  also settles the stamping inference for the four services that gained git.
- a deliberate error (a malformed id on a public GET) appears in Sentry
  tagged `service:<svc>` with that release within a minute.
- booking: the 02:00 Europe/London run shows as an `ok` check-in on
  `booking-generate-sessions` the next morning. payments:
  `payments-reconcile-capacity` shows `ok` check-ins every five minutes.
- the alert rule's `lastTriggered` moves on the first new production issue.

## Risks and rollback

- panic handling. If the reorder is wrong the symptom is an empty 200 on a
  panicking route. The unit test exists to make that impossible to ship;
  reviewers should still read the two lines. Revert: `git revert` of the one
  PR.
- cron monitors upsert on first check-in. A typo in the schedule produces
  false "missed" issues until fixed. Both schedules are copied verbatim from
  the manifests and commented as paired.
- ordering between homelab and service PRs. If a service deploys before its
  CronJob has `SENTRY_DSN`, `runMonitored` runs with no client, gets a nil
  check-in ID and skips reporting. Nothing breaks; the monitor simply does
  not exist yet. Merge homelab first anyway.
- `obs/v0.3.0` makes `Capture` fields into tags. Tag values are indexed and
  capped at 200 characters; the fields in use are ids, short strings, so no
  cardinality problem. Worth knowing before anyone passes a request body.
- alert email volume. Production only, first-seen and regression only, 30
  minute floor. If a noisy issue class appears, resolve or archive it in
  Sentry rather than loosening the rule.

## Sequence

1. homelab PR: CronJob `SENTRY_DSN`. Merge first.
2. schema PR.
3. booking and payments PRs (reorder, cron, monitor, tests).
4. community, gateway, notifications, video PRs (reorder, tests, Dockerfile
   git where missing).
5. Sentry alert rule, created once step 3 is open so there is something to
   alert on. Configuration above is the record.
6. follow-up issues: `obs.Recoverer` and `obs.RunMonitored` in `go-modules`;
   silent-500 sweep per service; browser SDK decision for web and admin;
   request-ID tagging; metric monitors after a week of traffic.
7. second round: the silent-500 sweeps. Done as stacked PRs; retarget each
   to `main` after its capture PR merges.
