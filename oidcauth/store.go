package oidcauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Schema is the SQL a consumer adds to its own migrations: the two tables this
// package reads and writes. Column names and types are part of the contract;
// a consumer embeds this text verbatim (or an equivalent CREATE TABLE) rather
// than renaming columns independently.
const Schema = `
CREATE TABLE users (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    subject    text NOT NULL UNIQUE,
    username   text NOT NULL DEFAULT '',
    name       text NOT NULL DEFAULT '',
    email      text NOT NULL DEFAULT '',
    avatar_url text NOT NULL DEFAULT '',
    groups     jsonb NOT NULL DEFAULT '[]',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id    bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token      text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
`

// User is a signed-in identity. Subject is the issuer's stable identifier
// (the sub claim), unique within one issuer. Groups is a snapshot taken at
// sign-in; a change at the issuer shows after the next sign-in.
type User struct {
	ID        int64     `json:"id"`
	Subject   string    `json:"subject"`
	Username  string    `json:"username"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	AvatarURL string    `json:"avatar_url"`
	Groups    []string  `json:"groups"`
	CreatedAt time.Time `json:"created_at"`
}

// Session is a signed-in session, keyed by an opaque bearer token held in a
// cookie. The sessions table's own primary key is not read, so a consumer
// with an existing sessions table keyed differently can keep it.
type Session struct {
	UserID    int64
	Token     string
	ExpiresAt time.Time
	CreatedAt time.Time
}

type sessionStore struct {
	db  *sql.DB
	now func() time.Time
}

const userColumns = `id, subject, username, name, email, avatar_url, groups, created_at`

func scanUser(row *sql.Row) (*User, error) {
	var u User
	var groups []byte
	if err := row.Scan(&u.ID, &u.Subject, &u.Username, &u.Name, &u.Email, &u.AvatarURL, &groups, &u.CreatedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(groups, &u.Groups); err != nil {
		return nil, fmt.Errorf("decode groups: %w", err)
	}
	return &u, nil
}

func (s *sessionStore) upsertUser(ctx context.Context, id *Identity) (*User, error) {
	groups := id.Groups
	if groups == nil {
		groups = []string{}
	}
	groupsJSON, err := json.Marshal(groups)
	if err != nil {
		return nil, fmt.Errorf("oidcauth: encode groups: %w", err)
	}
	// groups is passed as text and cast: lib/pq sends []byte as bytea, which
	// jsonb rejects, while a string works with both lib/pq and pgx.
	u, err := scanUser(s.db.QueryRowContext(ctx, `
		INSERT INTO users (subject, username, name, email, avatar_url, groups)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb)
		ON CONFLICT (subject) DO UPDATE SET
			username = EXCLUDED.username,
			name = EXCLUDED.name,
			email = EXCLUDED.email,
			avatar_url = EXCLUDED.avatar_url,
			groups = EXCLUDED.groups
		RETURNING `+userColumns,
		id.Subject, id.Username, id.Name, id.Email, id.AvatarURL, string(groupsJSON),
	))
	if err != nil {
		return nil, fmt.Errorf("oidcauth: upsert user: %w", err)
	}
	return u, nil
}

// create inserts the session and sweeps the user's expired ones, so a browser
// that never returns does not leave its row behind forever.
func (s *sessionStore) create(ctx context.Context, userID int64, token string, ttl time.Duration) error {
	now := s.now()
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM sessions WHERE user_id = $1 AND expires_at < $2`, userID, now); err != nil {
		return fmt.Errorf("oidcauth: sweep expired sessions: %w", err)
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (user_id, token, expires_at) VALUES ($1, $2, $3)`,
		userID, token, now.Add(ttl))
	if err != nil {
		return fmt.Errorf("oidcauth: create session: %w", err)
	}
	return nil
}

// findByToken returns (nil, nil) for a missing or expired token: missing and
// expired are the same thing to a caller deciding whether a request is
// authenticated.
func (s *sessionStore) findByToken(ctx context.Context, token string) (*Session, error) {
	var sess Session
	err := s.db.QueryRowContext(ctx,
		`SELECT user_id, token, expires_at, created_at FROM sessions WHERE token = $1`,
		token,
	).Scan(&sess.UserID, &sess.Token, &sess.ExpiresAt, &sess.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("oidcauth: find session: %w", err)
	}
	if s.now().After(sess.ExpiresAt) {
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
	u, err := scanUser(s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, id))
	if err != nil {
		return nil, fmt.Errorf("oidcauth: find user: %w", err)
	}
	return u, nil
}
