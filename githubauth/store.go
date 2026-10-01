package githubauth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Schema is the SQL a consumer adds to its own migrations: the two tables this
// package reads and writes. Column names and types are part of the contract —
// a consumer embeds this text verbatim (or an equivalent CREATE TABLE) rather
// than renaming columns independently.
const Schema = `
CREATE TABLE users (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    github_id    bigint NOT NULL UNIQUE,
    github_login text NOT NULL,
    name         text NOT NULL DEFAULT '',
    email        text NOT NULL DEFAULT '',
    avatar_url   text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id    bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token      text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
`

// User is a signed-in GitHub identity.
type User struct {
	ID          int64     `json:"id"`
	GitHubID    int64     `json:"github_id"`
	GitHubLogin string    `json:"github_login"`
	Name        string    `json:"name"`
	Email       string    `json:"email"`
	AvatarURL   string    `json:"avatar_url"`
	CreatedAt   time.Time `json:"created_at"`
}

// Session is a signed-in session, keyed by an opaque bearer token held in a
// cookie.
type Session struct {
	ID        int64
	UserID    int64
	Token     string
	ExpiresAt time.Time
	CreatedAt time.Time
}

type sessionStore struct{ db *sql.DB }

func (s *sessionStore) upsertUser(ctx context.Context, gh *githubUser) (*User, error) {
	var u User
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO users (github_id, github_login, name, email, avatar_url)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (github_id) DO UPDATE SET
			github_login = EXCLUDED.github_login,
			name = EXCLUDED.name,
			email = EXCLUDED.email,
			avatar_url = EXCLUDED.avatar_url
		RETURNING id, github_id, github_login, name, email, avatar_url, created_at`,
		gh.ID, gh.Login, gh.Name, gh.Email, gh.AvatarURL,
	).Scan(&u.ID, &u.GitHubID, &u.GitHubLogin, &u.Name, &u.Email, &u.AvatarURL, &u.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("githubauth: upsert user: %w", err)
	}
	return &u, nil
}

func (s *sessionStore) create(ctx context.Context, userID int64, token string, ttl time.Duration) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (user_id, token, expires_at) VALUES ($1, $2, $3)`,
		userID, token, time.Now().Add(ttl))
	if err != nil {
		return fmt.Errorf("githubauth: create session: %w", err)
	}
	return nil
}

// findByToken returns (nil, nil) for a missing or expired token — missing and
// expired are the same thing to a caller deciding whether a request is
// authenticated.
func (s *sessionStore) findByToken(ctx context.Context, token string) (*Session, error) {
	var sess Session
	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, token, expires_at, created_at FROM sessions WHERE token = $1`,
		token,
	).Scan(&sess.ID, &sess.UserID, &sess.Token, &sess.ExpiresAt, &sess.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("githubauth: find session: %w", err)
	}
	if time.Now().After(sess.ExpiresAt) {
		// Detached context: the request context is cancelled before this could
		// otherwise run.
		go s.delete(context.WithoutCancel(ctx), token)
		return nil, nil
	}
	return &sess, nil
}

func (s *sessionStore) delete(ctx context.Context, token string) {
	_, _ = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token = $1`, token)
}

func (s *sessionStore) findUserByID(ctx context.Context, id int64) (*User, error) {
	var u User
	err := s.db.QueryRowContext(ctx,
		`SELECT id, github_id, github_login, name, email, avatar_url, created_at FROM users WHERE id = $1`,
		id,
	).Scan(&u.ID, &u.GitHubID, &u.GitHubLogin, &u.Name, &u.Email, &u.AvatarURL, &u.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("githubauth: find user: %w", err)
	}
	return &u, nil
}
