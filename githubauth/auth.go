// Package githubauth gates an HTTP service behind GitHub sign-in, optionally
// restricted to an allowlist of GitHub logins. Call New once at startup,
// mount the four handlers, and wrap whatever routes need a session with
// RequireAuth:
//
//	auth, err := githubauth.New(db, githubauth.Config{
//		ClientID:      os.Getenv("GITHUB_CLIENT_ID"),
//		ClientSecret:  os.Getenv("GITHUB_CLIENT_SECRET"),
//		RedirectURL:   "https://app.example.com/auth/callback",
//		BaseURL:       "https://app.example.com",
//		AllowedLogins: []string{"octocat"},
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
// This is classic OAuth 2.0 (authorization code + PKCE), not OpenID Connect:
// GitHub does not issue ID tokens for human sign-in. GitHub's own use of the
// term "OIDC" (token.actions.githubusercontent.com) is a separate mechanism —
// workload identity federation for GitHub Actions — with no bearing on a
// person logging into a website.
package githubauth

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"
)

const (
	oauthStateCookie    = "githubauth_oauth_state"
	oauthVerifierCookie = "githubauth_oauth_verifier"
	oauthFlowTTL        = 10 * time.Minute
	sessionTTL          = 7 * 24 * time.Hour
)

// Config configures Auth. ClientID, ClientSecret, RedirectURL, and BaseURL are
// required.
type Config struct {
	// ClientID and ClientSecret identify the GitHub OAuth App (registered at
	// github.com/settings/developers).
	ClientID     string
	ClientSecret string
	// RedirectURL is the GitHub OAuth App's registered callback URL, e.g.
	// "https://app.example.com/auth/callback".
	RedirectURL string
	// BaseURL is the service's own public URL, e.g. "https://app.example.com".
	// A successful login redirects to BaseURL + PostLoginPath.
	BaseURL string
	// PostLoginPath is where a successful login redirects to, relative to
	// BaseURL. Defaults to "/".
	PostLoginPath string
	// AllowedLogins restricts sign-in to these GitHub logins. A login not on
	// the list is rejected at the OAuth callback — no session is ever created
	// for it. Empty means any authenticated GitHub user may sign in.
	AllowedLogins []string
	// CookieName names the session cookie. Defaults to "session".
	CookieName string
	// Secure sets the Secure flag on every cookie this package writes. State
	// this explicitly rather than relying on a default: true when the service
	// is only reachable over HTTPS (behind a TLS-terminating ingress or
	// gateway), false only for plain-HTTP local development.
	Secure bool
	// OAuthBaseURL and APIBaseURL default to the real GitHub endpoints.
	// Override both to point at a mock server for a deterministic test.
	OAuthBaseURL string
	APIBaseURL   string
}

// Auth wires GitHub OAuth and session handling against the configured
// database.
type Auth struct {
	cfg      Config
	github   *githubClient
	sessions *sessionStore
}

// New validates cfg, applies defaults, and builds an Auth.
func New(db *sql.DB, cfg Config) (*Auth, error) {
	var missing []string
	if cfg.ClientID == "" {
		missing = append(missing, "ClientID")
	}
	if cfg.ClientSecret == "" {
		missing = append(missing, "ClientSecret")
	}
	if cfg.RedirectURL == "" {
		missing = append(missing, "RedirectURL")
	}
	if cfg.BaseURL == "" {
		missing = append(missing, "BaseURL")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("githubauth: missing required config: %v", missing)
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "session"
	}
	if cfg.PostLoginPath == "" {
		cfg.PostLoginPath = "/"
	}
	if cfg.OAuthBaseURL == "" {
		cfg.OAuthBaseURL = "https://github.com"
	}
	if cfg.APIBaseURL == "" {
		cfg.APIBaseURL = "https://api.github.com"
	}

	return &Auth{
		cfg: cfg,
		github: &githubClient{
			clientID: cfg.ClientID, clientSecret: cfg.ClientSecret, redirectURL: cfg.RedirectURL,
			oauthBaseURL: cfg.OAuthBaseURL, apiBaseURL: cfg.APIBaseURL,
			httpClient: &http.Client{Timeout: 10 * time.Second},
		},
		sessions: &sessionStore{db: db},
	}, nil
}

// LoginHandler starts the OAuth flow: generates PKCE and state, stashes them
// in short-lived HttpOnly cookies, and redirects to GitHub.
func (a *Auth) LoginHandler(w http.ResponseWriter, r *http.Request) {
	state, err := generateState()
	if err != nil {
		a.internalError(w, err)
		return
	}
	verifier, challenge, err := generatePKCE()
	if err != nil {
		a.internalError(w, err)
		return
	}

	a.setCookie(w, oauthStateCookie, state, oauthFlowTTL)
	a.setCookie(w, oauthVerifierCookie, verifier, oauthFlowTTL)
	http.Redirect(w, r, a.github.authURL(state, challenge), http.StatusFound)
}

// CallbackHandler completes the OAuth flow: verifies state, exchanges the
// code, fetches the GitHub identity, enforces AllowedLogins, and creates a
// session. A login not on AllowedLogins is rejected here — no session is ever
// created for it.
func (a *Auth) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	stateCookie, err := r.Cookie(oauthStateCookie)
	if err != nil || subtle.ConstantTimeCompare([]byte(state), []byte(stateCookie.Value)) != 1 {
		http.Error(w, "invalid OAuth state", http.StatusBadRequest)
		return
	}
	verifierCookie, err := r.Cookie(oauthVerifierCookie)
	if err != nil {
		http.Error(w, "invalid OAuth state", http.StatusBadRequest)
		return
	}
	// Clear immediately: single-use, defence in depth.
	a.clearCookie(w, oauthStateCookie)
	a.clearCookie(w, oauthVerifierCookie)

	accessToken, err := a.github.exchangeCode(r.Context(), code, verifierCookie.Value)
	if err != nil {
		a.internalError(w, err)
		return
	}
	ghUser, err := a.github.getUser(r.Context(), accessToken)
	if err != nil {
		a.internalError(w, err)
		return
	}

	if len(a.cfg.AllowedLogins) > 0 && !slices.Contains(a.cfg.AllowedLogins, ghUser.Login) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	user, err := a.sessions.upsertUser(r.Context(), ghUser)
	if err != nil {
		a.internalError(w, err)
		return
	}
	token, err := generateSessionToken()
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

// LogoutHandler deletes the session (if any) and clears the cookie.
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

// RequireAuth rejects a request with no valid session, and otherwise attaches
// the signed-in User to the request context for UserFromContext.
func (a *Auth) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(a.cfg.CookieName)
		if err != nil || c.Value == "" {
			writeJSONError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		session, err := a.sessions.findByToken(r.Context(), c.Value)
		if err != nil {
			a.internalError(w, err)
			return
		}
		if session == nil {
			writeJSONError(w, http.StatusUnauthorized, "invalid session")
			return
		}
		user, err := a.sessions.findUserByID(r.Context(), session.UserID)
		if err != nil {
			a.internalError(w, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userCtxKey, user)))
	})
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

func (a *Auth) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: a.cfg.Secure, SameSite: http.SameSiteLaxMode,
	})
}

// internalError responds generically. This package has no logging dependency
// by design (it stays stdlib-only); the consumer's own request-logging
// middleware sees the resulting 500 and status code regardless.
func (a *Auth) internalError(w http.ResponseWriter, _ error) {
	writeJSONError(w, http.StatusInternalServerError, "internal error")
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{Error: message})
}
