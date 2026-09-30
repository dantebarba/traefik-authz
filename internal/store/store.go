// Package store keeps users, discovered apps, grants and access requests in
// SQLite, through the pure Go modernc.org/sqlite driver.
//
// E-mail addresses and hosts are normalized (see NormalizeEmail and
// NormalizeHost) on every write and lookup, so callers may pass them as they
// arrive in HTTP headers or Docker labels.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Errors returned by Store methods: ErrNotFound when the user, app or request
// does not exist, ErrExists when a user with that e-mail address already
// exists, and ErrInvalid for an e-mail address or host that cannot be stored.
var (
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("already exists")
	ErrInvalid  = errors.New("invalid value")
)

const schema = `
CREATE TABLE IF NOT EXISTS users (
	email      TEXT PRIMARY KEY,
	name       TEXT NOT NULL DEFAULT '',
	disabled   INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS apps (
	id        INTEGER PRIMARY KEY,
	host      TEXT NOT NULL UNIQUE,
	router    TEXT NOT NULL,
	name      TEXT NOT NULL,
	icon      TEXT NOT NULL DEFAULT '',
	last_seen INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS grants (
	user_email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
	app_id     INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
	PRIMARY KEY (user_email, app_id)
);
CREATE TABLE IF NOT EXISTS access_requests (
	email        TEXT NOT NULL,
	host         TEXT NOT NULL,
	requested_at INTEGER NOT NULL,
	PRIMARY KEY (email, host)
);
`

// User is a person who may be granted apps.
type User struct {
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Disabled  bool      `json:"disabled"`
	CreatedAt time.Time `json:"created_at"`
	AppIDs    []int64   `json:"app_ids"`
}

// App is a host guarded by the authz middleware, as found by discovery.
type App struct {
	ID       int64     `json:"id"`
	Host     string    `json:"host"`
	Router   string    `json:"router"`
	Name     string    `json:"name"`
	Icon     string    `json:"icon"`
	LastSeen time.Time `json:"last_seen"`
}

// Request is a denied attempt by an authenticated user to reach a known app.
type Request struct {
	Email       string    `json:"email"`
	Host        string    `json:"host"`
	RequestedAt time.Time `json:"requested_at"`
}

// Grantee is the part of a user that authorization needs.
type Grantee struct {
	Disabled bool
	AppIDs   map[int64]bool
}

// Snapshot is everything authorization reads, loaded at once so it can be
// cached: apps by host and users by e-mail address.
type Snapshot struct {
	Apps  map[string]App
	Users map[string]Grantee
}

// Store is an open database.
type Store struct {
	db *sql.DB
}

// Open opens or creates the database at path and applies the schema. The
// path ":memory:" opens a private in-memory database.
func Open(path string) (*Store, error) {
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, fmt.Errorf("create database directory: %w", err)
		}
	}
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error {
	return s.db.Close()
}

// NormalizeEmail returns the canonical form of an e-mail address: trimmed and
// lowercased.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// NormalizeHost returns the canonical form of a host: trimmed, lowercased,
// without a port and without a trailing dot.
func NormalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.TrimSuffix(host, ".")
}

func validEmail(email string) bool {
	local, domain, ok := strings.Cut(email, "@")
	return ok && local != "" && domain != "" && !strings.ContainsAny(email, " \t\r\n<>,;") && !strings.Contains(domain, "@")
}

func unix(t time.Time) int64 {
	return t.Unix()
}

func fromUnix(sec int64) time.Time {
	return time.Unix(sec, 0).UTC()
}

// AddUser creates an enabled user.
func (s *Store) AddUser(ctx context.Context, email, name string, now time.Time) (User, error) {
	email = NormalizeEmail(email)
	if !validEmail(email) {
		return User{}, fmt.Errorf("%w: e-mail address %q", ErrInvalid, email)
	}
	name = strings.TrimSpace(name)
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO users (email, name, disabled, created_at) VALUES (?, ?, 0, ?) ON CONFLICT (email) DO NOTHING`,
		email, name, unix(now))
	if err != nil {
		return User{}, err
	}
	if n, err := res.RowsAffected(); err != nil {
		return User{}, err
	} else if n == 0 {
		return User{}, ErrExists
	}
	return User{Email: email, Name: name, CreatedAt: fromUnix(unix(now)), AppIDs: []int64{}}, nil
}

// SetDisabled disables or re-enables a user. A disabled user keeps its
// grants but is denied everywhere.
func (s *Store) SetDisabled(ctx context.Context, email string, disabled bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET disabled = ? WHERE email = ?`, disabled, NormalizeEmail(email))
	if err != nil {
		return err
	}
	return requireRow(res)
}

// DeleteUser removes a user and its grants.
func (s *Store) DeleteUser(ctx context.Context, email string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE email = ?`, NormalizeEmail(email))
	if err != nil {
		return err
	}
	return requireRow(res)
}

func requireRow(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListUsers returns every user, ordered by e-mail address, with the ids of
// the apps granted to it.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT email, name, disabled, created_at FROM users ORDER BY email`)
	if err != nil {
		return nil, err
	}
	users := []User{}
	index := map[string]int{}
	for rows.Next() {
		var u User
		var created int64
		if err := rows.Scan(&u.Email, &u.Name, &u.Disabled, &created); err != nil {
			rows.Close()
			return nil, err
		}
		u.CreatedAt = fromUnix(created)
		u.AppIDs = []int64{}
		index[u.Email] = len(users)
		users = append(users, u)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	grants, err := s.db.QueryContext(ctx, `SELECT user_email, app_id FROM grants ORDER BY app_id`)
	if err != nil {
		return nil, err
	}
	defer grants.Close()
	for grants.Next() {
		var email string
		var id int64
		if err := grants.Scan(&email, &id); err != nil {
			return nil, err
		}
		if i, ok := index[email]; ok {
			users[i].AppIDs = append(users[i].AppIDs, id)
		}
	}
	return users, grants.Err()
}

// Grant gives a user access to an app and drops the user's pending request
// for it, if any.
func (s *Store) Grant(ctx context.Context, email string, appID int64) error {
	email = NormalizeEmail(email)
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if err := exists(ctx, tx, `SELECT 1 FROM users WHERE email = ?`, email); err != nil {
			return err
		}
		var host string
		if err := tx.QueryRowContext(ctx, `SELECT host FROM apps WHERE id = ?`, appID).Scan(&host); err != nil {
			return notFound(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO grants (user_email, app_id) VALUES (?, ?) ON CONFLICT DO NOTHING`, email, appID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM access_requests WHERE email = ? AND host = ?`, email, host)
		return err
	})
}

// Revoke takes an app away from a user. Revoking a grant that does not exist
// is not an error.
func (s *Store) Revoke(ctx context.Context, email string, appID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM grants WHERE user_email = ? AND app_id = ?`, NormalizeEmail(email), appID)
	return err
}

// UpsertApp records a discovered app, keyed by host, and marks it seen at
// the given time. Apps are never deleted, so their grants survive a
// container that goes away.
func (s *Store) UpsertApp(ctx context.Context, app App, seen time.Time) error {
	host := NormalizeHost(app.Host)
	if host == "" {
		return fmt.Errorf("%w: empty host", ErrInvalid)
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO apps (host, router, name, icon, last_seen) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (host) DO UPDATE SET
			router = excluded.router, name = excluded.name, icon = excluded.icon, last_seen = excluded.last_seen`,
		host, app.Router, app.Name, app.Icon, unix(seen))
	return err
}

// ListApps returns every app ever discovered, ordered by name and host.
func (s *Store) ListApps(ctx context.Context) ([]App, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, host, router, name, icon, last_seen FROM apps ORDER BY name COLLATE NOCASE, host`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	apps := []App{}
	for rows.Next() {
		a, err := scanApp(rows)
		if err != nil {
			return nil, err
		}
		apps = append(apps, a)
	}
	return apps, rows.Err()
}

func scanApp(rows *sql.Rows) (App, error) {
	var a App
	var seen int64
	if err := rows.Scan(&a.ID, &a.Host, &a.Router, &a.Name, &a.Icon, &seen); err != nil {
		return App{}, err
	}
	a.LastSeen = fromUnix(seen)
	return a, nil
}

// RecordRequest stores a denied attempt, keeping one entry per user and host
// with the time of the latest attempt.
func (s *Store) RecordRequest(ctx context.Context, email, host string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO access_requests (email, host, requested_at) VALUES (?, ?, ?)
		ON CONFLICT (email, host) DO UPDATE SET requested_at = excluded.requested_at`,
		NormalizeEmail(email), NormalizeHost(host), unix(at))
	return err
}

// ListRequests returns the pending access requests, newest first.
func (s *Store) ListRequests(ctx context.Context) ([]Request, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT email, host, requested_at FROM access_requests ORDER BY requested_at DESC, email, host`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	requests := []Request{}
	for rows.Next() {
		var r Request
		var at int64
		if err := rows.Scan(&r.Email, &r.Host, &at); err != nil {
			return nil, err
		}
		r.RequestedAt = fromUnix(at)
		requests = append(requests, r)
	}
	return requests, rows.Err()
}

// DismissRequest drops a pending request without granting anything.
func (s *Store) DismissRequest(ctx context.Context, email, host string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM access_requests WHERE email = ? AND host = ?`, NormalizeEmail(email), NormalizeHost(host))
	if err != nil {
		return err
	}
	return requireRow(res)
}

// ApproveRequest grants the app at host to the user, creating the user if it
// does not exist yet, and drops the request. A disabled user stays disabled.
func (s *Store) ApproveRequest(ctx context.Context, email, host string, now time.Time) error {
	email = NormalizeEmail(email)
	if !validEmail(email) {
		return fmt.Errorf("%w: e-mail address %q", ErrInvalid, email)
	}
	host = NormalizeHost(host)
	return s.inTx(ctx, func(tx *sql.Tx) error {
		var appID int64
		if err := tx.QueryRowContext(ctx, `SELECT id FROM apps WHERE host = ?`, host).Scan(&appID); err != nil {
			return notFound(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO users (email, name, disabled, created_at) VALUES (?, '', 0, ?) ON CONFLICT (email) DO NOTHING`, email, unix(now)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO grants (user_email, app_id) VALUES (?, ?) ON CONFLICT DO NOTHING`, email, appID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM access_requests WHERE email = ? AND host = ?`, email, host)
		return err
	})
}

// Snapshot loads every app and every user's grants.
func (s *Store) Snapshot(ctx context.Context) (Snapshot, error) {
	snap := Snapshot{Apps: map[string]App{}, Users: map[string]Grantee{}}
	apps, err := s.ListApps(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	for _, a := range apps {
		snap.Apps[a.Host] = a
	}
	users, err := s.ListUsers(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	for _, u := range users {
		g := Grantee{Disabled: u.Disabled, AppIDs: make(map[int64]bool, len(u.AppIDs))}
		for _, id := range u.AppIDs {
			g.AppIDs[id] = true
		}
		snap.Users[u.Email] = g
	}
	return snap, nil
}

func (s *Store) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func exists(ctx context.Context, tx *sql.Tx, query string, args ...any) error {
	var one int
	return notFound(tx.QueryRowContext(ctx, query, args...).Scan(&one))
}

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
