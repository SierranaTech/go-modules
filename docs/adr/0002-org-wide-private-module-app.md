# One org-wide GitHub App for private Go modules

## Context

Fetching a private module in CI needs a token. The
`SierranaTech/actions/private-modules-token` composite mints one from a
GitHub App and installs a global git credential helper that rewrites all
`github.com` fetches to use it. Running the composite twice in one job
does not work: the second token overwrites the first for every fetch. So
a repo that needs both `stiwdiohouse-contracts` and `go-modules` must
have both repos under a single App.

Every stiwdiohouse Go service will adopt `go-modules` (at least `obs`),
and three of them already depend on `stiwdiohouse-contracts`. The
"single App" case is therefore forced for those repos, and splitting the
rest across a second App buys nothing.

## Decision

Evolve the existing `private_gomod_stiwdiohouse` instance of the
`iac/modules/private-go-mods` module into one org-wide instance:

- rename it to something org-neutral (`sierranatech-modules`), with a
  `moved {}` block so the state migrates cleanly.
- its OIDC trust list grows to every Go consumer repo in the org.
- its App is installed on `go-modules` as well as `stiwdiohouse-contracts`,
  with `Contents: Read`.
- each consumer keeps making one `private-modules-token` call, naming
  whichever of the two module repos it actually imports.

## Considered options

- **A separate App and instance for `go-modules`**, plus reworking the
  composite to merge multiple tokens (per-repo git config instead of a
  blanket rewrite). Cleaner separation, but it changes a composite that
  other repos rely on and adds a second App to operate. Rejected: not
  worth it for two module repos.

## Consequences

- This is an auth change: it widens an OIDC trust policy across ~20 repos
  and adds an App installation. It gets its own security review, separate
  from the module code.
- The instance name stops matching the client project it started as. The
  rename is the tell that it is now org infrastructure.
- Adding a future private module repo means installing this App on it and
  adding it to a consumer's `repositories` list, not standing up new
  infrastructure.
