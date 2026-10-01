module github.com/SierranaTech/go-modules

go 1.27.1

// jackc/pgx is test-only (githubauth/githubauth_test.go uses pgx/v5/stdlib to
// exercise the package's database/sql-only code against real Postgres). Test
// files never compile into an importing consumer's build, so this does not
// add to a consumer's dependency graph; the root module's packages stay
// stdlib-only per ADR 0001.
require github.com/jackc/pgx/v5 v5.11.0

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/text v0.29.0 // indirect
)
