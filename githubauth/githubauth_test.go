package githubauth_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/SierranaTech/go-modules/githubauth"
)

// newTestDB opens an isolated, schema-applied Postgres database for one test,
// dropped on cleanup. Skips when TEST_DATABASE_URL is unset.
//
// This package's own code (store.go) imports only database/sql — never a
// driver. pgx/v5/stdlib here is a test-only dependency, used exactly as a
// consumer would use it to build the *sql.DB that New takes. Test files are
// never compiled into an importing consumer's build, so this doesn't add
// anything to a consumer's dependency graph; it only proves this package
// against the real thing instead of a fake.
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	adminDSN := os.Getenv("TEST_DATABASE_URL")
	if adminDSN == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping database integration test")
	}
	ctx := context.Background()
	name := "githubauth_test_" + randToken()

	withAdmin(t, adminDSN, func(admin *sql.DB) {
		if _, err := admin.ExecContext(ctx, `CREATE DATABASE `+quoteIdent(name)); err != nil {
			t.Fatalf("create database %s: %v", name, err)
		}
	})
	t.Cleanup(func() {
		withAdmin(t, adminDSN, func(admin *sql.DB) {
			if _, err := admin.ExecContext(context.Background(), `DROP DATABASE IF EXISTS `+quoteIdent(name)+` WITH (FORCE)`); err != nil {
				t.Logf("cleanup: drop database %s: %v", name, err)
			}
		})
	})

	testDSN := swapDBName(t, adminDSN, name)
	db, err := sql.Open("pgx", testDSN)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(ctx, githubauth.Schema); err != nil {
		t.Fatalf("apply schema: %v", err)
	}
	return db
}

func withAdmin(t *testing.T, dsn string, fn func(*sql.DB)) {
	t.Helper()
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open admin connection: %v", err)
	}
	defer func() { _ = admin.Close() }()
	fn(admin)
}

func randToken() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

func swapDBName(t *testing.T, dsn, name string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse TEST_DATABASE_URL: %v", err)
	}
	u.Path = "/" + name
	return u.String()
}

// mockGitHubUser is the fixture shape returned by the mock GitHub server's
// /user endpoint, matching GitHub's real field names.
type mockGitHubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

// newMockGitHub fakes the two endpoints the OAuth exchange needs: token
// exchange and the authenticated user lookup. It does not validate PKCE or the
// authorization code's value — that's GitHub's own job, out of scope for
// testing this package's callback logic.
func newMockGitHub(t *testing.T, user mockGitHubUser) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "mock-access-token"})
	})
	mux.HandleFunc("GET /user", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(user)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// authStack wires an Auth against a mock GitHub and a real database, mounted
// behind a jar-carrying http.Client so cookies flow between requests exactly
// as they would in a browser.
type authStack struct {
	auth   *githubauth.Auth
	srv    *httptest.Server
	client *http.Client
}

func newAuthStack(t *testing.T, allowedLogins []string, ghUser mockGitHubUser) *authStack {
	t.Helper()
	db := newTestDB(t)
	gh := newMockGitHub(t, ghUser)

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	auth, err := githubauth.New(db, githubauth.Config{
		ClientID: "test-client", ClientSecret: "test-secret",
		RedirectURL: srv.URL + "/auth/callback", BaseURL: srv.URL,
		AllowedLogins: allowedLogins,
		OAuthBaseURL:  gh.URL, APIBaseURL: gh.URL,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	mux.HandleFunc("GET /auth/login", auth.LoginHandler)
	mux.HandleFunc("GET /auth/callback", auth.CallbackHandler)
	mux.HandleFunc("POST /auth/logout", auth.LogoutHandler)
	mux.Handle("GET /auth/me", auth.RequireAuth(http.HandlerFunc(auth.MeHandler)))
	mux.Handle("GET /protected", auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, _ := githubauth.UserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(u)
	})))

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return &authStack{auth: auth, srv: srv, client: &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // inspect redirects instead of following
		},
	}}
}

// login drives GET /auth/login then GET /auth/callback through the stack's
// cookie-jar client, exactly as a browser completing the OAuth dance would.
// Returns the callback's response so the caller can assert its outcome.
func (s *authStack) login(t *testing.T) *http.Response {
	t.Helper()
	loginResp, err := s.client.Get(s.srv.URL + "/auth/login")
	if err != nil {
		t.Fatalf("GET /auth/login: %v", err)
	}
	defer func() { _ = loginResp.Body.Close() }()
	if loginResp.StatusCode != http.StatusFound {
		t.Fatalf("GET /auth/login status = %d, want 302", loginResp.StatusCode)
	}
	loc, err := loginResp.Location()
	if err != nil {
		t.Fatalf("login redirect has no Location: %v", err)
	}
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatal("login redirect URL has no state parameter")
	}

	callbackURL := s.srv.URL + "/auth/callback?code=fake-code&state=" + state
	callbackResp, err := s.client.Get(callbackURL)
	if err != nil {
		t.Fatalf("GET /auth/callback: %v", err)
	}
	return callbackResp
}

func TestLoginFlowCreatesSessionAndAuthenticates(t *testing.T) {
	s := newAuthStack(t, nil, mockGitHubUser{ID: 1, Login: "octocat", Name: "The Octocat", Email: "octocat@example.com"})

	resp := s.login(t)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback status = %d, want 302", resp.StatusCode)
	}
	if loc, _ := resp.Location(); loc.String() != s.srv.URL+"/" {
		t.Fatalf("callback redirected to %q, want %q", loc, s.srv.URL+"/")
	}

	protResp, err := s.client.Get(s.srv.URL + "/protected")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = protResp.Body.Close() }()
	if protResp.StatusCode != http.StatusOK {
		t.Fatalf("protected route status = %d, want 200", protResp.StatusCode)
	}
	var user githubauth.User
	if err := json.NewDecoder(protResp.Body).Decode(&user); err != nil {
		t.Fatal(err)
	}
	if user.GitHubLogin != "octocat" {
		t.Fatalf("user.GitHubLogin = %q, want octocat", user.GitHubLogin)
	}
}

func TestLoginRejectedWhenNotOnAllowedLogins(t *testing.T) {
	s := newAuthStack(t, []string{"octocat"}, mockGitHubUser{ID: 2, Login: "intruder"})

	resp := s.login(t)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("callback status = %d, want 403", resp.StatusCode)
	}

	protResp, err := s.client.Get(s.srv.URL + "/protected")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = protResp.Body.Close() }()
	if protResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("protected route status = %d, want 401 (no session should exist)", protResp.StatusCode)
	}
}

func TestProtectedRouteRejectsNoCookie(t *testing.T) {
	s := newAuthStack(t, nil, mockGitHubUser{ID: 1, Login: "octocat"})
	resp, err := http.Get(s.srv.URL + "/protected") // no jar: no cookie
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestLogoutEndsTheSession(t *testing.T) {
	s := newAuthStack(t, nil, mockGitHubUser{ID: 1, Login: "octocat"})
	s.login(t)

	logoutResp, err := s.client.Post(s.srv.URL+"/auth/logout", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = logoutResp.Body.Close()

	protResp, err := s.client.Get(s.srv.URL + "/protected")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = protResp.Body.Close() }()
	if protResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status after logout = %d, want 401", protResp.StatusCode)
	}
}
