# OpenID Connect sign-in trusts TLS to the issuer, not token signatures

`oidcauth` is a confidential client using the authorization code flow. It
receives the ID token directly from the issuer's token endpoint over TLS and
reads the user's claims from the userinfo endpoint over TLS. We decided not to
verify the ID token's signature, and so not to depend on `coreos/go-oidc` and
`golang.org/x/oauth2`. The package stays stdlib-only in the root module, as
ADR 0001 wants for everything that is not a heavy dependency.

OpenID Connect Core 3.1.3.7, step 6, allows exactly this: when the ID token is
received over a direct TLS connection to the token endpoint, TLS server
validation may stand in for the signature check. The package still validates
`iss`, `aud`, `exp` and `nonce`, and requires the userinfo `sub` to match. What
it does not defend against is a compromised certificate authority or an
`IssuerURL` pointing somewhere other than the real issuer, which `New` guards
by refusing a non-loopback `http://` issuer.

## Considered options

- **`go-oidc` and `x/oauth2` as a submodule**, with JWKS signature
  verification. Standard, nothing to explain to a reviewer, and already used
  in `stiwdiohouse-video` and `microservice-operator`. Rejected: a second tag
  namespace and CI matrix entry, and a `heavy dependency` ruling for a library
  whose main job would be a check the trust model does not need. go-modules#21
  suggested it as one example, not a requirement.
- **Hand-written RS256 verification against the issuer's JWKS.** Possible with
  `crypto/rsa` alone, but it is security-critical code we would own, for the
  same gain as above.

## Consequences

- every security review of a consumer will ask why there is no signature
  check. The answer is this ADR and the comment on `parseIDToken`.
- the trust model only holds for the code flow with a confidential client. If
  a consumer ever needs the ID token from a browser (implicit or hybrid flow),
  or to accept tokens it did not fetch itself, signature verification becomes
  mandatory and this decision is superseded.
