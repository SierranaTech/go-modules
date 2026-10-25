# Engineering plan: `oidcauth`, and vocatio-frontend's move to Authelia

Implements go-modules#21. homelab ADR 0007 decided that in-house apps sign in
through Authelia over OpenID Connect and that go-modules gains a generic
OpenID Connect package next to `githubauth`, with the same shape. This plan
covers the package, its release, and the first consumer swap: vocatio-frontend.
vidistet (#47), faucepan (#40) and copywrite (#77) follow in their own PRs.

Written 2026-10-25 after a grill-with-docs session. The decisions below that
were open were put to the owner and settled; the rest come from ADR 0007, the
live Authelia discovery document and the consumer's code.

## Decisions

- stdlib only, in the root module. No `go-oidc`, no `x/oauth2`. The ID token
  arrives directly from the token endpoint over TLS, so TLS is the trust anchor
  and the token's signature is not checked. ADR 0003 records why.
- claims come from the userinfo endpoint, not the ID token. Authelia 4.39 puts
  only the core claims in the ID token unless the client carries a
  `claims_policy`; userinfo always has them. The `sub` from userinfo must match
  the ID token's.
- `AllowedGroups` in `Config`, checked against the `groups` claim at the
  callback. Empty means any authenticated user. Authelia's per-client
  `authorization_policy` stays the primary gate for our own apps.
- `githubauth` stays, marked deprecated. It is removed once vocatio-frontend
  and vidistet have moved, and that removal is the `v1.0.0` tag. The root
  module is `v0` today, so this change is `v0.3.0`.
- discovery is lazy: fetched on the first login and cached. A fetch in `New`
  would turn an Authelia outage into a crash loop on restart, which ADR 0007
  promises does not happen ("sessions the apps already hold keep working").
- logout is local only. Authelia's discovery document has no
  `end_session_endpoint` (checked 2026-10-25), so there is nothing to call.
- time is injected through `Config.Now`, so session expiry and ID token `exp`
  are testable without sleeping.

## Ponytail pass

Smaller version considered: a forward-auth sidecar per app, trusting a header
from Authelia. Rejected in ADR 0007 for our own code. The next smaller
version: `go-oidc` as a submodule and no hand-written token handling. Rejected
above; it costs a second tag namespace and a `heavy dependency` ruling for a
library that would do signature checks the trust model does not need.

What we are not doing: refresh tokens or `offline_access` (sessions are local,
seven days, like `githubauth`); back-channel or RP-initiated logout; signed or
encrypted userinfo; multiple issuers per deployment; storing access tokens.

## The package

`github.com/SierranaTech/go-modules/oidcauth`, root module, stdlib only.

```go
auth, err := oidcauth.New(db, oidcauth.Config{
    IssuerURL:     "https://auth.sierrana.co.uk",
    ClientID:      os.Getenv("OIDC_CLIENT_ID"),
    ClientSecret:  os.Getenv("OIDC_CLIENT_SECRET"),
    RedirectURL:   "https://app.example.com/auth/callback",
    BaseURL:       "https://app.example.com",
    AllowedGroups: []string{"app-users"},
    Secure:        true,
})
mux.HandleFunc("GET /auth/login", auth.LoginHandler)
mux.HandleFunc("GET /auth/callback", auth.CallbackHandler)
mux.HandleFunc("POST /auth/logout", auth.LogoutHandler)
mux.HandleFunc("GET /auth/me", auth.MeHandler)
protected := auth.RequireAuth(restOfTheMux)
```

`Config`: `IssuerURL`, `ClientID`, `ClientSecret`, `RedirectURL`, `BaseURL`
(required); `PostLoginPath` (default `/`); `Scopes` (default `openid profile
email groups`); `AllowedGroups`; `CookieName` (default `session`); `Secure`;
`Unauthenticated http.Handler`; `Now func() time.Time` (default `time.Now`).
No endpoint overrides: a test points `IssuerURL` at an in-process fake issuer
that serves discovery, authorization, token and userinfo.

`User`: `ID`, `Subject`, `Username` (`preferred_username`), `Name`, `Email`,
`AvatarURL` (`picture`), `Groups`, `CreatedAt`. Groups are a snapshot taken at
sign-in; a group change in Authelia shows after the next sign-in.

### Files

- `oidcauth/auth.go`: `Config`, `New`, the four handlers, `RequireAuth`,
  `UserFromContext`, cookies. Mirrors `githubauth/auth.go`.
- `oidcauth/provider.go`: discovery (lazy, cached), authorization URL, code
  exchange with `client_secret_basic` and PKCE, userinfo fetch.
- `oidcauth/idtoken.go`: `parseIDToken(raw, issuer, clientID, nonce, now)`,
  a pure function returning the claims or an error. The seam for unit tests.
- `oidcauth/store.go`: `Schema`, `User`, `Session`, the SQL. Same as
  `githubauth/store.go` with the identity columns changed.
- `oidcauth/idtoken_test.go`: table tests on `parseIDToken`, no database.
- `oidcauth/oidcauth_test.go`: end-to-end against a fake issuer and a real
  Postgres (`TEST_DATABASE_URL`, skipped when unset), same harness shape as
  `githubauth_test.go`.

### Flow

Login: generate `state`, `nonce` and a PKCE verifier; write each to a ten
minute HttpOnly cookie; redirect to the authorization endpoint with
`response_type=code`, `scope`, `state`, `nonce`, `code_challenge` (S256).

Callback, in order; every failure clears the flow cookies:

1. `error=access_denied` from the issuer is a 403 `forbidden`. Any other
   `error` is a 400.
2. `state` must equal the cookie, constant-time. Otherwise 400.
3. exchange `code` plus the verifier at the token endpoint, HTTP Basic with
   the client credentials. A non-200 or an `error` body is a 500.
4. `parseIDToken`: three dot-separated segments; base64url-decode the
   payload; `iss` equals `IssuerURL`; `aud` (string or array) contains
   `ClientID`; `exp` is after `Now()`; `nonce` equals the cookie. Any
   failure is a 400 `invalid ID token`. No signature check; see ADR 0003.
5. GET userinfo with the access token as a bearer. Its `sub` must equal the
   ID token's, else 400.
6. `AllowedGroups`, when set, must intersect the `groups` claim. Otherwise
   403 `forbidden` and no session.
7. upsert the user on `subject`, create a session, set the cookie, redirect
   to `BaseURL + PostLoginPath`.

Discovery is fetched from `IssuerURL + /.well-known/openid-configuration` on
first use, under a mutex, and kept once it succeeds. Its `issuer` must equal
`IssuerURL` or the fetch fails. A failed fetch is a 500 on that request and is
retried on the next.

### Schema

```sql
CREATE TABLE users (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    subject    text NOT NULL UNIQUE,
    username   text NOT NULL DEFAULT '',
    name       text NOT NULL DEFAULT '',
    email      text NOT NULL DEFAULT '',
    avatar_url text NOT NULL DEFAULT '',
    groups     jsonb NOT NULL DEFAULT '[]',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE sessions (...)  -- unchanged from githubauth
```

`subject` is unique per issuer. One issuer per deployment, so pointing an app
at a different issuer means new user rows.

### Tests

Unit, no database:

- `parseIDToken` accepts a valid token; rejects wrong issuer, missing
  audience, string and array `aud`, expiry at and after `exp` with an injected
  clock, nonce mismatch, malformed segments and payloads.

End-to-end, fake issuer plus Postgres, cookie-jar client:

- login creates a session and `MeHandler` returns the user with groups.
- a user outside `AllowedGroups` gets 403 and no session row.
- `access_denied` from the issuer is a 403.
- a tampered `state` is a 400.
- userinfo `sub` that differs from the ID token's is a 400.
- a protected route with no cookie is a 401, or runs `Unauthenticated`.
- logout deletes the session and clears the cookie.
- a session is rejected once the injected clock passes its expiry.
- the first login fails with 500 while discovery is unreachable and
  succeeds once the issuer answers, without restarting.

The fake issuer records the `nonce` from the authorization request and puts
it in the ID token, checks HTTP Basic on the token endpoint, and checks the
bearer token on userinfo.

## Release

Merge, then `git tag v0.3.0 && git push origin v0.3.0`. The root module is
`v0`, so a new package is a minor bump. Deprecating `githubauth` is a doc
comment, not a break.

## vocatio-frontend swap

Four PRs, in this order. Each step leaves the app signing in.

1. **iac, `environments/aws/authelia.tf`**: a `random_password` for the
   vocatio-frontend client, 64 alphanumeric characters, following the Flux
   pattern. Plaintext to `/apps/vocatio-frontend/oidc/client-secret`, bcrypt
   digest to `/apps/authelia/clients/vocatio-frontend/client-secret-digest`.
   Both roles already read those prefixes. Plan is produced by iac's CI; the
   owner applies.
2. **homelab, Authelia and vocatio-frontend together**:
   - `manifests/authelia/`: group `vocatio-users` on `simeon`; authorization
     policy `vocatio-users` (deny by default, `two_factor` for the group);
     client `vocatio-frontend` with the digest through the ExternalSecret,
     `require_pkce` S256, redirect URI
     `https://vocatio.taild816.ts.net/auth/callback`, scopes `openid profile
     email groups`, `authorization_code` only, `client_secret_basic`,
     `consent_mode: pre-configured` for one week as the Flux clients do.
   - `manifests/vocatio-frontend/`: add `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`,
     `ALLOWED_GROUPS` to `config` and `OIDC_CLIENT_SECRET` to `secretRefs`.
     Keep the `GITHUB_*` entries: the running image still needs them.
3. **vocatio-frontend**: bump go-modules to `v0.3.0`; `config` reads
   `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`,
   `OIDC_REDIRECT_URL` (optional) and `ALLOWED_GROUPS` (required, refuses to
   start without one, as it does today for logins); `main` swaps to
   `oidcauth.New`; `sessiondb.Open` drops a GitHub-shaped `users` and
   `sessions` pair before applying the new schema. The database holds sign-in
   sessions only, so nothing is lost beyond forcing one sign-in. README
   updated. Flux rolls the new image once CI pushes it.
4. **homelab cleanup**: remove the `GITHUB_*` config and secretRefs from the
   vocatio-frontend Microservice. A follow-up issue in iac narrows the
   vocatio-frontend external-secrets role away from
   `/infra/github-apps/sierranatech-authenticity/*` once vidistet has moved
   too.

## Checks

- covered by unit tests: `parseIDToken` rules; the callback's rejection paths;
  session creation, lookup, expiry and deletion; group gating; lazy discovery.
- after step 3 deploys: from a fresh browser, `https://vocatio.taild816.ts.net`
  redirects to Authelia, two factors, then the mail list loads. Sign out and
  the next request redirects to Authelia again. A user outside
  `vocatio-users` is refused by Authelia before reaching the app.
- after step 2: OpenCloud, openclaw and the Flux UIs still sign in.

## Rollback

- step 3: revert the vocatio-frontend PR. Flux rolls the previous image, which
  reads the `GITHUB_*` variables still present until step 4. The GitHub-shaped
  tables are gone; `sessiondb.Open` recreates them on an absent `users` table
  only, so the revert also needs a manual `DROP TABLE sessions, users`.
- step 2: revert the homelab PR. The SSM parameters can stay.
- go-modules: `oidcauth` is additive; nothing to roll back.

## Risks

- the callback trusts TLS to the issuer instead of a signature. A compromised
  CA or a misconfigured `IssuerURL` (plain `http://`) would defeat it. `New`
  rejects an `IssuerURL` that is not `https://` unless it is a loopback
  address, which is what tests use.
- Authelia's own `authorization_policy` and the module's `AllowedGroups`
  both gate. If they disagree, Authelia wins and the module's 403 is never
  reached for our apps; the module's check matters for other issuers.
- egress: vocatio-frontend on homelab must reach `auth.sierrana.co.uk` on
  production over the public URL. The namespace has no network policy today,
  so nothing blocks it; the after-deploy check proves it.
