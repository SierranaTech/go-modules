package githubauth

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
)

// githubClient speaks GitHub's classic OAuth 2.0 authorization-code flow —
// the only sign-in mechanism GitHub offers for a human user. GitHub's own use
// of the term "OIDC" (token.actions.githubusercontent.com) is a separate thing
// entirely: workload identity federation for GitHub Actions, with no bearing
// on a person logging into a website.
type githubClient struct {
	clientID     string
	clientSecret string
	redirectURL  string
	oauthBaseURL string
	apiBaseURL   string
	httpClient   *http.Client
}

func (g *githubClient) authURL(state, codeChallenge string) string {
	u, _ := url.Parse(g.oauthBaseURL + "/login/oauth/authorize")
	q := u.Query()
	q.Set("client_id", g.clientID)
	q.Set("redirect_uri", g.redirectURL)
	q.Set("scope", "read:user user:email")
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String()
}

func (g *githubClient) exchangeCode(ctx context.Context, code, codeVerifier string) (string, error) {
	data := url.Values{
		"client_id":     {g.clientID},
		"client_secret": {g.clientSecret},
		"code":          {code},
		"redirect_uri":  {g.redirectURL},
		"code_verifier": {codeVerifier},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		g.oauthBaseURL+"/login/oauth/access_token", strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("githubauth: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("githubauth: token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return "", fmt.Errorf("githubauth: read token response: %w", err)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("githubauth: parse token response: %w", err)
	}
	if tokenResp.Error != "" {
		return "", fmt.Errorf("githubauth: github token error: %s", tokenResp.Error)
	}
	return tokenResp.AccessToken, nil
}

type githubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

func (g *githubClient) getUser(ctx context.Context, accessToken string) (*githubUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.apiBaseURL+"/user", nil)
	if err != nil {
		return nil, fmt.Errorf("githubauth: build user request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("githubauth: user request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("githubauth: read user response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("githubauth: github user request returned %d: %s", resp.StatusCode, string(body))
	}

	var user githubUser
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, fmt.Errorf("githubauth: parse user response: %w", err)
	}
	if user.Email == "" {
		user.Email, _ = g.fetchPrimaryEmail(ctx, accessToken)
	}
	return &user, nil
}

func (g *githubClient) fetchPrimaryEmail(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.apiBaseURL+"/user/emails", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	var emails []struct {
		Email   string `json:"email"`
		Primary bool   `json:"primary"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&emails); err != nil {
		return "", err
	}
	for _, e := range emails {
		if e.Primary {
			return e.Email, nil
		}
	}
	return "", nil
}

// generatePKCE returns a code_verifier and its S256 code_challenge for PKCE
// (RFC 7636).
func generatePKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("githubauth: generate pkce verifier: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge, nil
}

func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("githubauth: generate state: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func generateSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("githubauth: generate session token: %w", err)
	}
	return hex.EncodeToString(b), nil
}
