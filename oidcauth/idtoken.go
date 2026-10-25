package oidcauth

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// claims is the subset of ID token and userinfo claims this package reads.
type claims struct {
	Issuer            string   `json:"iss"`
	Subject           string   `json:"sub"`
	Audience          audience `json:"aud"`
	AuthorizedParty   string   `json:"azp"`
	Expiry            int64    `json:"exp"`
	Nonce             string   `json:"nonce"`
	PreferredUsername string   `json:"preferred_username"`
	Name              string   `json:"name"`
	Email             string   `json:"email"`
	Picture           string   `json:"picture"`
	Groups            []string `json:"groups"`
}

// audience accepts the aud claim as either a single string or an array, both
// of which OpenID Connect allows.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return fmt.Errorf("aud is neither a string nor an array of strings")
	}
	*a = audience(many)
	return nil
}

// parseIDToken decodes an ID token and checks iss, aud, exp and nonce.
//
// It does not verify the signature. The token arrives directly from the
// issuer's token endpoint over TLS, which OpenID Connect Core 3.1.3.7 step 6
// allows in place of a signature check; TLS to the issuer is the trust anchor
// (ADR 0003). That holds only for a confidential client fetching the token
// itself. Never feed this function a token that came from a browser or any
// other third party.
func parseIDToken(raw, issuer, clientID, nonce string, now time.Time) (*claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("oidcauth: ID token is not a three-part JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil, fmt.Errorf("oidcauth: decode ID token payload: %w", err)
	}
	var c claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("oidcauth: parse ID token payload: %w", err)
	}
	if strings.TrimSuffix(c.Issuer, "/") != issuer {
		return nil, fmt.Errorf("oidcauth: ID token issuer %q is not %q", c.Issuer, issuer)
	}
	if !slices.Contains(c.Audience, clientID) {
		return nil, fmt.Errorf("oidcauth: ID token audience %v does not include this client", []string(c.Audience))
	}
	// OpenID Connect Core 3.1.3.7 steps 4 and 5: with several audiences the
	// token must name this client as the authorized party.
	if len(c.Audience) > 1 && c.AuthorizedParty != clientID {
		return nil, fmt.Errorf("oidcauth: ID token azp %q is not this client", c.AuthorizedParty)
	}
	if c.Expiry == 0 || !now.Before(time.Unix(c.Expiry, 0)) {
		return nil, errors.New("oidcauth: ID token has expired")
	}
	if c.Nonce == "" || subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(nonce)) != 1 {
		return nil, errors.New("oidcauth: ID token nonce mismatch")
	}
	if c.Subject == "" {
		return nil, errors.New("oidcauth: ID token has no sub")
	}
	return &c, nil
}
