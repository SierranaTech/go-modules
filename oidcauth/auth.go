// Package oidcauth gates an HTTP service behind OpenID Connect sign-in,
// optionally restricted to members of given groups. Call New once at startup,
// mount the four handlers, and wrap whatever routes need a session with
// RequireAuth:
//
//	auth, err := oidcauth.New(db, oidcauth.Config{
//		IssuerURL:     "https://auth.example.com",
//		ClientID:      os.Getenv("OIDC_CLIENT_ID"),
//		ClientSecret:  os.Getenv("OIDC_CLIENT_SECRET"),
//		RedirectURL:   "https://app.example.com/auth/callback",
//		BaseURL:       "https://app.example.com",
//		AllowedGroups: []string{"app-users"},
//		Secure:        true,
//	})
//	mux.HandleFunc("GET /auth/login", auth.LoginHandler)
//	mux.HandleFunc("GET /auth/callback", auth.CallbackHandler)
//	mux.HandleFunc("POST /auth/logout", auth.LogoutHandler)
//	mux.HandleFunc("GET /auth/me", auth.MeHandler)
//	protected := auth.RequireAuth(restOfTheMux)
//
// Sessions and users persist in the *sql.DB passed to New; see Schema for the
// two required tables, added to the consumer's own migrations.
//
// The package is a confidential client using the authorization code flow with
// PKCE and a nonce. It reads the user's claims from the userinfo endpoint and
// trusts TLS to the issuer rather than verifying the ID token's signature; see
// docs/adr/0003 and parseIDToken for the reasoning and its limits.
package oidcauth

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const (
	flowStateCookie    = "oidcauth_state"
	flowNonceCookie    = "oidcauth_nonce"
	flowVerifierCookie = "oidcauth_verifier"
	flowTTL            = 10 * time.Minute
	sessionTTL         = 7 * 24 * time.Hour
)

var defaultScopes = []string{"openid", "profile", "email", "groups"}

// Config configures Auth. IssuerURL, ClientID, ClientSecret, RedirectURL and
// BaseURL are required.
type Config struct {
	// IssuerURL is the OpenID Connect issuer, e.g. "https://auth.example.com".
	// Discovery is read from IssuerURL + "/.well-known/openid-configuration",
	// and the ID token's iss claim must equal it. It must be https, except a
	// loopback address for tests.
	IssuerURL string
	// ClientID and ClientSecret identify this app's client at the issuer. The
	// secret is sent with client_secret_basic, form-encoded per RFC 6749
	// 2.3.1; an alphanumeric secret avoids any disagreement over that.
	ClientID     string
	ClientSecret string
	// RedirectURL is the client's registered callback URL, e.g.
	// "https://app.example.com/auth/callback".
	RedirectURL string
	// BaseURL is the service's own public URL, e.g. "https://app.example.com".
	// A successful login redirects to BaseURL + PostLoginPath.
	BaseURL string
	// PostLoginPath is where a successful login redirects to, relative to
	// BaseURL. Defaults to "/".
	PostLoginPath string
	// Scopes requested at sign-in. Defaults to openid, profile, email and
	// groups. Authelia only issues the groups claim when groups is requested.
	Scopes []string
	// AllowedGroups restricts sign-in to users whose groups claim contains at
	// least one of these. A user outside them is rejected at the callback and
	// no session is ever created. Empty means any authenticated user may sign
	// in.
	AllowedGroups []string
	// CookieName names the session cookie. Defaults to "session".
	CookieName string
	// Secure sets the Secure flag on every cookie this package writes. State
	// this explicitly rather than relying on a default: true when the service
	// is only reachable over HTTPS, false only for plain-HTTP local
	// development.
	Secure bool
	// Unauthenticated, when set, handles a request RequireAuth rejects for a
	// missing or invalid session, e.g. to redirect a browser to LoginHandler.
	// Nil writes a JSON 401.
	Unauthenticated http.Handler
	// Now returns the current time. Defaults to time.Now; a test injects a
	// clock to drive session and ID token expiry.
	Now func() time.Time
}

// Auth wires OpenID Connect sign-in and session handling against the
// configured database.
type Auth struct {
	cfg      Config
	provider *provider
	sessions *sessionStore
}

// New validates cfg, applies defaults, and builds an Auth. It makes no network
// calls: discovery runs on the first login, so an issuer outage does not stop
// the service starting.
func New(db *sql.DB, cfg Config) (*Auth, error) {
	var missing []string
	for _, f := range []struct{ name, value string }{
		{"IssuerURL", cfg.IssuerURL}, {"ClientID", cfg.ClientID}, {"ClientSecret", cfg.ClientSecret},
		{"RedirectURL", cfg.RedirectURL}, {"BaseURL", cfg.BaseURL},
	} {
		if f.value == "" {
			missing = append(missing, f.name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("oidcauth: missing required config: %v", missing)
	}
	cfg.IssuerURL = strings.TrimSuffix(cfg.IssuerURL, "/")
	if err := checkHTTPSURL(cfg.IssuerURL); err != nil {
		return nil, fmt.Errorf("oidcauth: IssuerURL: %w", err)
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "session"
	}
	if cfg.PostLoginPath == "" {
		cfg.PostLoginPath = "/"
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = defaultScopes
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	return &Auth{
		cfg: cfg,
		provider: &provider{
			issuer: cfg.IssuerURL, clientID: cfg.ClientID, clientSecret: cfg.ClientSecret,
			redirectURL: cfg.RedirectURL, scopes: strings.Join(cfg.Scopes, " "),
			httpClient: &http.Client{Timeout: 10 * time.Second},
		},
		sessions: &sessionStore{db: db, now: cfg.Now},
	}, nil
}

// checkHTTPSURL enforces https for the issuer and every endpoint it
// advertises. TLS to the issuer is this package's trust anchor (ADR 0003), so
// a plain-http URL would mean trusting an unauthenticated network path.
// Loopback is allowed for tests.
func checkHTTPSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%q is not an absolute URL", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" || net.ParseIP(host).IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("%q must be https (http is allowed for loopback only)", raw)
}

// LoginHandler starts the sign-in: generates state, nonce and PKCE, stashes
// them in short-lived HttpOnly cookies, and redirects to the issuer.
func (a *Auth) LoginHandler(w http.ResponseWriter, r *http.Request) {
	state, err := randomToken()
	if err != nil {
		a.internalError(w, err)
		return
	}
	nonce, err := randomToken()
	if err != nil {
		a.internalError(w, err)
		return
	}
	verifier, challenge, err := generatePKCE()
	if err != nil {
		a.internalError(w, err)
		return
	}
	target, err := a.provider.authURL(r.Context(), state, nonce, challenge)
	if err != nil {
		a.internalError(w, err)
		return
	}

	a.setCookie(w, flowStateCookie, state, flowTTL)
	a.setCookie(w, flowNonceCookie, nonce, flowTTL)
	a.setCookie(w, flowVerifierCookie, verifier, flowTTL)
	http.Redirect(w, r, target, http.StatusFound)
}

// CallbackHandler completes the sign-in: verifies state, exchanges the code,
// validates the ID token, fetches userinfo, enforces AllowedGroups, and
// creates a session. A user outside AllowedGroups is rejected here; no
// session is ever created for them.
func (a *Auth) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	stateCookie, stateErr := r.Cookie(flowStateCookie)
	nonceCookie, nonceErr := r.Cookie(flowNonceCookie)
	verifierCookie, verifierErr := r.Cookie(flowVerifierCookie)

	// The issuer reports a refused sign-in (e.g. a user outside the client's
	// authorization policy) as an error redirect rather than a code.
	if e := q.Get("error"); e != "" {
		a.clearFlowCookies(w)
		if e == "access_denied" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		http.Error(w, "sign-in failed: "+e, http.StatusBadRequest)
		return
	}
	if stateErr != nil || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(stateCookie.Value)) != 1 ||
		nonceErr != nil || verifierErr != nil || q.Get("code") == "" {
		http.Error(w, "invalid sign-in state", http.StatusBadRequest)
		return
	}
	// Cleared only once the state matched: a stray cross-site request to the
	// callback must not be able to abort someone else's sign-in. Single-use
	// from here on, defence in depth.
	a.clearFlowCookies(w)

	tokens, err := a.provider.exchangeCode(r.Context(), q.Get("code"), verifierCookie.Value)
	if err != nil {
		a.internalError(w, err)
		return
	}
	idToken, err := parseIDToken(tokens.IDToken, a.cfg.IssuerURL, a.cfg.ClientID, nonceCookie.Value, a.cfg.Now())
	if err != nil {
		http.Error(w, "invalid ID token", http.StatusBadRequest)
		return
	}
	info, err := a.provider.userinfo(r.Context(), tokens.AccessToken)
	if err != nil {
		a.internalError(w, err)
		return
	}
	if info.Subject != idToken.Subject {
		http.Error(w, "invalid ID token", http.StatusBadRequest)
		return
	}

	if len(a.cfg.AllowedGroups) > 0 && !slices.ContainsFunc(info.Groups, func(g string) bool {
		return slices.Contains(a.cfg.AllowedGroups, g)
	}) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	user, err := a.sessions.upsertUser(r.Context(), info)
	if err != nil {
		a.internalError(w, err)
		return
	}
	token, err := randomToken()
	if err != nil {
		a.internalError(w, err)
		return
	}
	if err := a.sessions.create(r.Context(), user.ID, token, sessionTTL); err != nil {
		a.internalError(w, err)
		return
	}

	a.setCookie(w, a.cfg.CookieName, token, sessionTTL)
	http.Redirect(w, r, a.cfg.BaseURL+a.cfg.PostLoginPath, http.StatusFound)
}

// LogoutHandler deletes the session (if any) and clears the cookie. It ends
// this app's session only; the issuer's own session is untouched.
func (a *Auth) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(a.cfg.CookieName); err == nil && c.Value != "" {
		a.sessions.delete(r.Context(), c.Value)
	}
	a.clearCookie(w, a.cfg.CookieName)
	http.Redirect(w, r, a.cfg.BaseURL+"/", http.StatusFound)
}

// MeHandler returns the signed-in User as JSON. Mount it behind RequireAuth.
func (a *Auth) MeHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := UserFromContext(r.Context())
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(user)
}

type ctxKey int

const userCtxKey ctxKey = iota

// ErrUnauthenticated is returned by Authenticate for a request with no
// session cookie, or a cookie naming a session that is missing or expired.
var ErrUnauthenticated = errors.New("oidcauth: not authenticated")

// Authenticate resolves the request's session cookie to its User. It returns
// ErrUnauthenticated when there is no valid session and any other error for a
// database failure. RequireAuth is built on it; a consumer on a router with
// its own middleware shape (gin, chi) calls it directly.
func (a *Auth) Authenticate(r *http.Request) (*User, error) {
	c, err := r.Cookie(a.cfg.CookieName)
	if err != nil || c.Value == "" {
		return nil, ErrUnauthenticated
	}
	session, err := a.sessions.findByToken(r.Context(), c.Value)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, ErrUnauthenticated
	}
	return a.sessions.findUserByID(r.Context(), session.UserID)
}

// RequireAuth rejects a request with no valid session, and otherwise attaches
// the signed-in User to the request context for UserFromContext.
func (a *Auth) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := a.Authenticate(r)
		if errors.Is(err, ErrUnauthenticated) {
			a.unauthenticated(w, r)
			return
		}
		if err != nil {
			a.internalError(w, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userCtxKey, user)))
	})
}

func (a *Auth) unauthenticated(w http.ResponseWriter, r *http.Request) {
	if a.cfg.Unauthenticated != nil {
		a.cfg.Unauthenticated.ServeHTTP(w, r)
		return
	}
	writeJSONError(w, http.StatusUnauthorized, "authentication required")
}

// UserFromContext returns the User attached by RequireAuth.
func UserFromContext(ctx context.Context) (*User, bool) {
	u, ok := ctx.Value(userCtxKey).(*User)
	return u, ok
}

func (a *Auth) setCookie(w http.ResponseWriter, name, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: int(ttl / time.Second),
		HttpOnly: true, Secure: a.cfg.Secure, SameSite: http.SameSiteLaxMode,
	})
}

func (a *Auth) clearFlowCookies(w http.ResponseWriter) {
	a.clearCookie(w, flowStateCookie)
	a.clearCookie(w, flowNonceCookie)
	a.clearCookie(w, flowVerifierCookie)
}

func (a *Auth) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: a.cfg.Secure, SameSite: http.SameSiteLaxMode,
	})
}

// internalError responds generically and logs the cause through the default
// slog logger, so an operator can tell a discovery, token, userinfo or
// database failure apart without the error reaching the browser.
func (a *Auth) internalError(w http.ResponseWriter, err error) {
	slog.Error("oidcauth: sign-in failed", "err", err)
	writeJSONError(w, http.StatusInternalServerError, "internal error")
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{Error: message})
}
