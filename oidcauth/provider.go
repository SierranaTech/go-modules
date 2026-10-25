package oidcauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

const maxBody = 1 << 16

// provider speaks the OpenID Connect authorization code flow to one issuer.
// Discovery is lazy and cached: the first login fetches it, a failure is
// retried on the next login, and a success is kept for the process lifetime.
type provider struct {
	issuer       string
	clientID     string
	clientSecret string
	redirectURL  string
	scopes       string
	httpClient   *http.Client

	mu   sync.Mutex
	disc *discovery
}

type discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

func (p *provider) discover(ctx context.Context) (*discovery, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.disc != nil {
		return p.disc, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, fmt.Errorf("oidcauth: build discovery request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	body, err := p.do(req, "discovery")
	if err != nil {
		return nil, err
	}
	var d discovery
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("oidcauth: parse discovery: %w", err)
	}
	if strings.TrimSuffix(d.Issuer, "/") != p.issuer {
		return nil, fmt.Errorf("oidcauth: discovery issuer %q does not match configured %q", d.Issuer, p.issuer)
	}
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.UserinfoEndpoint == "" {
		return nil, fmt.Errorf("oidcauth: discovery is missing an endpoint")
	}
	p.disc = &d
	return p.disc, nil
}

func (p *provider) authURL(ctx context.Context, state, nonce, codeChallenge string) (string, error) {
	d, err := p.discover(ctx)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(d.AuthorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("oidcauth: parse authorization endpoint: %w", err)
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", p.clientID)
	q.Set("redirect_uri", p.redirectURL)
	q.Set("scope", p.scopes)
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	IDToken          string `json:"id_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// exchangeCode redeems the authorization code at the token endpoint,
// authenticating with client_secret_basic. Per RFC 6749 2.3.1 the credentials
// are form-encoded before going into the Basic header.
func (p *provider) exchangeCode(ctx context.Context, code, codeVerifier string) (*tokenResponse, error) {
	d, err := p.discover(ctx)
	if err != nil {
		return nil, err
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.redirectURL},
		"code_verifier": {codeVerifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oidcauth: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(p.clientID), url.QueryEscape(p.clientSecret))

	body, err := p.do(req, "token")
	if err != nil {
		return nil, err
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("oidcauth: parse token response: %w", err)
	}
	if tr.Error != "" {
		return nil, fmt.Errorf("oidcauth: token endpoint error: %s: %s", tr.Error, tr.ErrorDescription)
	}
	if tr.AccessToken == "" || tr.IDToken == "" {
		return nil, fmt.Errorf("oidcauth: token response is missing a token")
	}
	return &tr, nil
}

// userinfo fetches the user's claims with the access token. The response is
// expected as plain JSON, the issuer's default; a client registered with a
// signed userinfo response is not supported.
func (p *provider) userinfo(ctx context.Context, accessToken string) (*claims, error) {
	d, err := p.discover(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.UserinfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("oidcauth: build userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	body, err := p.do(req, "userinfo")
	if err != nil {
		return nil, err
	}
	var c claims
	if err := json.Unmarshal(body, &c); err != nil {
		return nil, fmt.Errorf("oidcauth: parse userinfo: %w", err)
	}
	if c.Subject == "" {
		return nil, fmt.Errorf("oidcauth: userinfo has no sub")
	}
	return &c, nil
}

// do sends req and returns the body of a 200 response.
func (p *provider) do(req *http.Request, what string) ([]byte, error) {
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidcauth: %s request: %w", what, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("oidcauth: read %s response: %w", what, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidcauth: %s request returned %d: %s", what, resp.StatusCode, string(body))
	}
	return body, nil
}

// generatePKCE returns a code_verifier and its S256 code_challenge for PKCE
// (RFC 7636).
func generatePKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("oidcauth: generate pkce verifier: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge, nil
}

// randomToken returns 256 bits of randomness as hex, used for state, nonce
// and session tokens.
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oidcauth: generate token: %w", err)
	}
	return hex.EncodeToString(b), nil
}
