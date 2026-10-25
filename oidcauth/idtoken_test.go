package oidcauth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func encodeSegment(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// unsignedToken builds a JWT with a junk signature: parseIDToken must not
// look at it.
func unsignedToken(t *testing.T, payload map[string]any) string {
	t.Helper()
	return encodeSegment(t, map[string]string{"alg": "RS256", "typ": "JWT"}) + "." +
		encodeSegment(t, payload) + "." + base64.RawURLEncoding.EncodeToString([]byte("not-a-signature"))
}

func TestParseIDToken(t *testing.T) {
	const issuer = "https://auth.example.com"
	const clientID = "app"
	const nonce = "n-1"
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	exp := now.Add(5 * time.Minute).Unix()

	base := func(edit func(map[string]any)) map[string]any {
		p := map[string]any{"iss": issuer, "sub": "user-1", "aud": clientID, "exp": exp, "nonce": nonce}
		if edit != nil {
			edit(p)
		}
		return p
	}

	cases := []struct {
		name    string
		token   string
		now     time.Time
		wantErr string
	}{
		{"valid with string aud", unsignedToken(t, base(nil)), now, ""},
		{"valid with array aud", unsignedToken(t, base(func(p map[string]any) { p["aud"] = []string{"other", clientID} })), now, ""},
		{"issuer trailing slash is tolerated", unsignedToken(t, base(func(p map[string]any) { p["iss"] = issuer + "/" })), now, ""},
		{"wrong issuer", unsignedToken(t, base(func(p map[string]any) { p["iss"] = "https://evil.example.com" })), now, "issuer"},
		{"audience excludes client", unsignedToken(t, base(func(p map[string]any) { p["aud"] = []string{"other"} })), now, "audience"},
		{"aud of wrong type", unsignedToken(t, base(func(p map[string]any) { p["aud"] = 42 })), now, "aud"},
		{"expired at exp", unsignedToken(t, base(nil)), time.Unix(exp, 0), "expired"},
		{"expired after exp", unsignedToken(t, base(nil)), time.Unix(exp, 0).Add(time.Hour), "expired"},
		{"exp missing", unsignedToken(t, base(func(p map[string]any) { delete(p, "exp") })), now, "expired"},
		{"nonce mismatch", unsignedToken(t, base(func(p map[string]any) { p["nonce"] = "n-2" })), now, "nonce"},
		{"nonce missing", unsignedToken(t, base(func(p map[string]any) { delete(p, "nonce") })), now, "nonce"},
		{"sub missing", unsignedToken(t, base(func(p map[string]any) { delete(p, "sub") })), now, "sub"},
		{"two segments", "a.b", now, "three-part"},
		{"payload not base64", "a.!!!.c", now, "decode"},
		{"payload not json", "a." + base64.RawURLEncoding.EncodeToString([]byte("nope")) + ".c", now, "parse"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseIDToken(tc.token, issuer, clientID, nonce, tc.now)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got.Subject != "user-1" {
					t.Errorf("Subject = %q", got.Subject)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want one mentioning %q", err, tc.wantErr)
			}
		})
	}
}
