package oidcauth_test

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/SierranaTech/go-modules/oidcauth"
)

// newTestDB opens an isolated, schema-applied Postgres database for one test,
// dropped on cleanup. Skips when TEST_DATABASE_URL is unset. pgx/v5/stdlib is
// test-only here, exactly as a consumer would use it to build the *sql.DB that
// New takes; the package itself imports only database/sql.
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	adminDSN := os.Getenv("TEST_DATABASE_URL")
	if adminDSN == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping database integration test")
	}
	ctx := context.Background()
	name := "oidcauth_test_" + randToken()

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

	u, err := url.Parse(adminDSN)
	if err != nil {
		t.Fatalf("parse TEST_DATABASE_URL: %v", err)
	}
	u.Path = "/" + name
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(ctx, oidcauth.Schema); err != nil {
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

// clock is the injected time source. Tests advance it instead of sleeping.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeIssuer is an in-process OpenID Connect provider: discovery,
// authorization (which redirects straight back with a code), token (which
// checks client_secret_basic, the code and a PKCE verifier) and userinfo
// (which checks the bearer token). It signs ID tokens with HS256 only so they
// look like real ones; the package under test does not verify them.
type fakeIssuer struct {
	srv          *httptest.Server
	clientID     string
	clientSecret string
	now          func() time.Time

	mu          sync.Mutex
	user        map[string]any
	lastNonce   string
	down        bool
	authError   string
	idTokenEdit func(map[string]any)
}

func newFakeIssuer(t *testing.T, user map[string]any, now func() time.Time) *fakeIssuer {
	t.Helper()
	f := &fakeIssuer{clientID: "test-client", clientSecret: "test-secret", user: user, now: now}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		down := f.down
		f.mu.Unlock()
		if down {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, map[string]string{
			"issuer":                 f.srv.URL,
			"authorization_endpoint": f.srv.URL + "/authorize",
			"token_endpoint":         f.srv.URL + "/token",
			"userinfo_endpoint":      f.srv.URL + "/userinfo",
		})
	})
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f.mu.Lock()
		f.lastNonce = q.Get("nonce")
		authError := f.authError
		f.mu.Unlock()
		back, err := url.Parse(q.Get("redirect_uri"))
		if err != nil {
			http.Error(w, "bad redirect_uri", http.StatusBadRequest)
			return
		}
		bq := back.Query()
		bq.Set("state", q.Get("state"))
		if authError != "" {
			bq.Set("error", authError)
		} else {
			bq.Set("code", "fake-code")
		}
		back.RawQuery = bq.Encode()
		http.Redirect(w, r, back.String(), http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		if !ok || id != f.clientID || secret != f.clientSecret {
			w.WriteHeader(http.StatusUnauthorized)
			writeJSON(w, map[string]string{"error": "invalid_client"})
			return
		}
		if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != "authorization_code" ||
			r.PostForm.Get("code") != "fake-code" || r.PostForm.Get("code_verifier") == "" {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]string{"error": "invalid_grant"})
			return
		}
		f.mu.Lock()
		payload := map[string]any{
			"iss": f.srv.URL, "sub": f.user["sub"], "aud": f.clientID,
			"exp": f.now().Add(5 * time.Minute).Unix(), "iat": f.now().Unix(), "nonce": f.lastNonce,
		}
		if f.idTokenEdit != nil {
			f.idTokenEdit(payload)
		}
		f.mu.Unlock()
		writeJSON(w, map[string]string{
			"access_token": "fake-access", "token_type": "Bearer", "id_token": signHS256(t, payload),
		})
	})
	mux.HandleFunc("GET /userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fake-access" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		writeJSON(w, f.user)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIssuer) set(fn func(*fakeIssuer)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func signHS256(t *testing.T, payload map[string]any) string {
	t.Helper()
	seg := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signingInput := seg(map[string]string{"alg": "HS256", "typ": "JWT"}) + "." + seg(payload)
	mac := hmac.New(sha256.New, []byte("fake-issuer-key"))
	mac.Write([]byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func defaultUser() map[string]any {
	return map[string]any{
		"sub": "user-1", "preferred_username": "alice", "name": "Alice Example",
		"email": "alice@example.com", "picture": "https://img.example.com/alice.png",
		"groups": []string{"app-users", "other"},
	}
}

// stack wires an Auth against a fake issuer and a real database, mounted
// behind a jar-carrying http.Client so cookies flow between requests exactly
// as they would in a browser.
type stack struct {
	db     *sql.DB
	clock  *clock
	issuer *fakeIssuer
	srv    *httptest.Server
	client *http.Client
	// noRedirect shares the jar but stops at the first redirect.
	noRedirect *http.Client
}

func newStack(t *testing.T, user map[string]any, mod func(*oidcauth.Config)) *stack {
	t.Helper()
	db := newTestDB(t)
	clk := &clock{t: time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)}
	issuer := newFakeIssuer(t, user, clk.Now)

	var auth *oidcauth.Auth
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/login", func(w http.ResponseWriter, r *http.Request) { auth.LoginHandler(w, r) })
	mux.HandleFunc("GET /auth/callback", func(w http.ResponseWriter, r *http.Request) { auth.CallbackHandler(w, r) })
	mux.HandleFunc("POST /auth/logout", func(w http.ResponseWriter, r *http.Request) { auth.LogoutHandler(w, r) })
	mux.Handle("GET /auth/me", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth.RequireAuth(http.HandlerFunc(auth.MeHandler)).ServeHTTP(w, r)
	}))
	mux.Handle("GET /protected", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, _ := oidcauth.UserFromContext(r.Context())
			_, _ = io.WriteString(w, "hello "+u.Username)
		})).ServeHTTP(w, r)
	}))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "home") })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cfg := oidcauth.Config{
		IssuerURL:    issuer.srv.URL,
		ClientID:     issuer.clientID,
		ClientSecret: issuer.clientSecret,
		RedirectURL:  srv.URL + "/auth/callback",
		BaseURL:      srv.URL,
		Now:          clk.Now,
	}
	if mod != nil {
		mod(&cfg)
	}
	var err error
	auth, err = oidcauth.New(db, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &stack{
		db: db, clock: clk, issuer: issuer, srv: srv,
		client: &http.Client{Jar: jar},
		noRedirect: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
	}
}

func (s *stack) get(t *testing.T, path string) (*http.Response, string) {
	t.Helper()
	resp, err := s.client.Get(s.srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

// login runs the whole redirect chain and returns the final response.
func (s *stack) login(t *testing.T) (*http.Response, string) {
	t.Helper()
	return s.get(t, "/auth/login")
}

func (s *stack) sessionCount(t *testing.T) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM sessions`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestLoginFlowCreatesSessionAndAuthenticates(t *testing.T) {
	s := newStack(t, defaultUser(), func(c *oidcauth.Config) { c.AllowedGroups = []string{"app-users"} })

	resp, body := s.login(t)
	if resp.StatusCode != http.StatusOK || body != "home" {
		t.Fatalf("login landed on %d %q, want 200 home", resp.StatusCode, body)
	}
	if n := s.sessionCount(t); n != 1 {
		t.Fatalf("sessions = %d, want 1", n)
	}

	resp, body = s.get(t, "/protected")
	if resp.StatusCode != http.StatusOK || body != "hello alice" {
		t.Fatalf("/protected = %d %q", resp.StatusCode, body)
	}

	resp, body = s.get(t, "/auth/me")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/auth/me = %d %q", resp.StatusCode, body)
	}
	var me oidcauth.User
	if err := json.Unmarshal([]byte(body), &me); err != nil {
		t.Fatal(err)
	}
	if me.Subject != "user-1" || me.Username != "alice" || me.Email != "alice@example.com" ||
		me.AvatarURL != "https://img.example.com/alice.png" || strings.Join(me.Groups, ",") != "app-users,other" {
		t.Errorf("me = %+v", me)
	}

	// Signing in again updates the same user rather than creating another.
	s.issuer.set(func(f *fakeIssuer) { f.user["name"] = "Alice Renamed" })
	s.login(t)
	var users int
	var name string
	if err := s.db.QueryRow(`SELECT count(*), max(name) FROM users`).Scan(&users, &name); err != nil {
		t.Fatal(err)
	}
	if users != 1 || name != "Alice Renamed" {
		t.Errorf("users = %d, name = %q", users, name)
	}
}

func TestLoginRejectedWhenNotInAllowedGroups(t *testing.T) {
	s := newStack(t, defaultUser(), func(c *oidcauth.Config) { c.AllowedGroups = []string{"admins"} })

	resp, _ := s.login(t)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("login = %d, want 403", resp.StatusCode)
	}
	if n := s.sessionCount(t); n != 0 {
		t.Fatalf("sessions = %d, want 0", n)
	}
	if resp, _ := s.get(t, "/protected"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/protected = %d, want 401", resp.StatusCode)
	}
}

func TestIssuerErrorRedirect(t *testing.T) {
	for name, tc := range map[string]struct {
		authError string
		want      int
	}{
		"access_denied is forbidden":   {"access_denied", http.StatusForbidden},
		"other errors are bad request": {"server_error", http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			s := newStack(t, defaultUser(), nil)
			s.issuer.set(func(f *fakeIssuer) { f.authError = tc.authError })
			resp, _ := s.login(t)
			if resp.StatusCode != tc.want {
				t.Fatalf("login = %d, want %d", resp.StatusCode, tc.want)
			}
			if n := s.sessionCount(t); n != 0 {
				t.Fatalf("sessions = %d, want 0", n)
			}
		})
	}
}

func TestTamperedStateRejected(t *testing.T) {
	s := newStack(t, defaultUser(), nil)

	// Start the flow so the state cookie exists, but stop at the redirect.
	resp, err := s.noRedirect.Get(s.srv.URL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login = %d, want 302", resp.StatusCode)
	}

	resp, _ = s.get(t, "/auth/callback?code=fake-code&state=wrong")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("callback = %d, want 400", resp.StatusCode)
	}
	if n := s.sessionCount(t); n != 0 {
		t.Fatalf("sessions = %d, want 0", n)
	}
}

func TestInvalidIDTokenRejected(t *testing.T) {
	for name, edit := range map[string]func(map[string]any){
		"nonce mismatch":                func(p map[string]any) { p["nonce"] = "someone-elses" },
		"audience is another app":       func(p map[string]any) { p["aud"] = "other-client" },
		"expired":                       func(p map[string]any) { p["exp"] = time.Date(2026, 10, 25, 11, 0, 0, 0, time.UTC).Unix() },
		"subject differs from userinfo": func(p map[string]any) { p["sub"] = "user-2" },
	} {
		t.Run(name, func(t *testing.T) {
			s := newStack(t, defaultUser(), nil)
			s.issuer.set(func(f *fakeIssuer) { f.idTokenEdit = edit })
			resp, _ := s.login(t)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("login = %d, want 400", resp.StatusCode)
			}
			if n := s.sessionCount(t); n != 0 {
				t.Fatalf("sessions = %d, want 0", n)
			}
		})
	}
}

func TestProtectedRouteRejectsNoCookie(t *testing.T) {
	s := newStack(t, defaultUser(), nil)
	resp, body := s.get(t, "/protected")
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "authentication required") {
		t.Fatalf("/protected = %d %q", resp.StatusCode, body)
	}
}

func TestUnauthenticatedHandlerReplacesDefault401(t *testing.T) {
	s := newStack(t, defaultUser(), func(c *oidcauth.Config) {
		c.Unauthenticated = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		})
	})
	resp, err := s.noRedirect.Get(s.srv.URL + "/protected")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/auth/login" {
		t.Fatalf("/protected = %d Location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestLogoutEndsTheSession(t *testing.T) {
	s := newStack(t, defaultUser(), nil)
	s.login(t)

	resp, err := s.client.Post(s.srv.URL+"/auth/logout", "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout landed on %d", resp.StatusCode)
	}
	if n := s.sessionCount(t); n != 0 {
		t.Fatalf("sessions = %d, want 0", n)
	}
	if resp, _ := s.get(t, "/protected"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/protected after logout = %d, want 401", resp.StatusCode)
	}
}

func TestSessionExpires(t *testing.T) {
	s := newStack(t, defaultUser(), nil)
	s.login(t)

	s.clock.Advance(7*24*time.Hour - time.Minute)
	if resp, _ := s.get(t, "/protected"); resp.StatusCode != http.StatusOK {
		t.Fatalf("/protected just before expiry = %d, want 200", resp.StatusCode)
	}
	s.clock.Advance(2 * time.Minute)
	if resp, _ := s.get(t, "/protected"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/protected after expiry = %d, want 401", resp.StatusCode)
	}
}

func TestDiscoveryRetriedAfterIssuerOutage(t *testing.T) {
	s := newStack(t, defaultUser(), nil)

	s.issuer.set(func(f *fakeIssuer) { f.down = true })
	if resp, _ := s.login(t); resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("login with issuer down = %d, want 500", resp.StatusCode)
	}

	s.issuer.set(func(f *fakeIssuer) { f.down = false })
	if resp, body := s.login(t); resp.StatusCode != http.StatusOK || body != "home" {
		t.Fatalf("login after recovery = %d %q, want 200 home", resp.StatusCode, body)
	}
}

func TestNewValidatesConfig(t *testing.T) {
	valid := oidcauth.Config{
		IssuerURL: "https://auth.example.com", ClientID: "c", ClientSecret: "s",
		RedirectURL: "https://app.example.com/auth/callback", BaseURL: "https://app.example.com",
	}
	if _, err := oidcauth.New(nil, valid); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	loopback := valid
	loopback.IssuerURL = "http://127.0.0.1:9999"
	if _, err := oidcauth.New(nil, loopback); err != nil {
		t.Fatalf("loopback http issuer rejected: %v", err)
	}

	plain := valid
	plain.IssuerURL = "http://auth.example.com"
	if _, err := oidcauth.New(nil, plain); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("plain http issuer: err = %v, want https requirement", err)
	}

	missing := valid
	missing.ClientSecret = ""
	missing.BaseURL = ""
	_, err := oidcauth.New(nil, missing)
	if err == nil || !strings.Contains(err.Error(), "ClientSecret") || !strings.Contains(err.Error(), "BaseURL") {
		t.Fatalf("missing fields: err = %v", err)
	}
}
