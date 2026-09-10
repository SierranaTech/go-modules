# go-modules

Shared Go code for SierranaTech services: the glue that every service was
copy-pasting (Sentry wiring, config and logging setup, HTTP middleware,
notification senders). One repo, several independently versioned modules,
consumed by every `ci` + `ecr` Go service in the org.

This is not the place for inter-service HTTP types. Those live in
`stiwdiohouse-contracts` (and any future per-project equivalent).

## Language

**Root module**:
The `go.mod` at the repo root, module path `github.com/SierranaTech/go-modules`.
Holds every stdlib-only package. Released with plain `vX.Y.Z` tags.
_Avoid_: main module, core module.

**Submodule**:
A subdirectory with its own `go.mod` and its own tag namespace
(`obs/vX.Y.Z`). One submodule per heavy third-party dependency, so that a
consumer of the root module never pulls that dependency.
_Avoid_: nested module, child module.

**Heavy dependency**:
A third-party dependency large enough that we do not want it in the build
graph of a service that did not ask for it: `getsentry/sentry-go`,
`jackc/pgx`, `sigs.k8s.io/controller-runtime`. Each one is quarantined in
its own submodule.
_Avoid_: big dep, external dep.

**Consumer**:
A service repo that imports one or more packages from here. Every consumer
pins a tag and lists `go-modules` in its `private-modules-token` call.
_Avoid_: client, importer, downstream.

**Migration PR**:
A single pull request in one consumer that replaces one hand-rolled copy
with the shared package. Behaviour-preserving, reviewable by diff, paired
with the one-line CI change that grants module access.
_Avoid_: adoption, rollout, port.

**Scrub list**:
The set of header names and form-field names that `obs` redacts from a
Sentry event before send. The module ships a safe default; a consumer may
add to it but cannot shrink it.
_Avoid_: denylist, filter list, redaction set.
