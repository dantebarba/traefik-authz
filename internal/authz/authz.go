// Package authz decides whether an authenticated user may reach a host.
//
// The rules, in order: no user is denied; an admin is allowed everywhere; an
// unknown host is denied; a user that is enabled and holds a grant on the
// host's app is allowed; everyone else is denied. What the rules read is
// cached in memory until Invalidate is called.
package authz

import (
	"context"
	"sync"

	"traefik-authz/internal/store"
)

// Reason says which rule decided: NoUser (the request carries no user, so no
// forward-auth ran before), Admin (the user is listed in ADMIN_EMAILS),
// UnknownHost (the host is not an app found by discovery), Granted (the user
// is enabled and holds a grant on the app), Disabled (the user exists but is
// disabled) or NotGranted (the user is unknown or holds no grant on the app).
type Reason string

const (
	NoUser      Reason = "no-user"
	Admin       Reason = "admin"
	UnknownHost Reason = "unknown-host"
	Granted     Reason = "granted"
	Disabled    Reason = "disabled"
	NotGranted  Reason = "not-granted"
)

// Decision is the outcome for one user and host.
type Decision struct {
	Allowed bool
	Reason  Reason
	Email   string
	Host    string
	App     store.App
}

// Source loads what the rules read.
type Source interface {
	Snapshot(ctx context.Context) (store.Snapshot, error)
}

// Authorizer applies the rules over a cached snapshot of a Source.
type Authorizer struct {
	admins map[string]bool
	source Source

	load  sync.Mutex
	mu    sync.RWMutex
	gen   uint64
	cache *store.Snapshot
}

// New returns an Authorizer for the given admin e-mail addresses.
func New(admins []string, source Source) *Authorizer {
	set := make(map[string]bool, len(admins))
	for _, a := range admins {
		if a = store.NormalizeEmail(a); a != "" {
			set[a] = true
		}
	}
	return &Authorizer{admins: set, source: source}
}

// IsAdmin reports whether email is one of the admin addresses.
func (a *Authorizer) IsAdmin(email string) bool {
	return a.admins[store.NormalizeEmail(email)]
}

// Admins returns the admin addresses, in no particular order.
func (a *Authorizer) Admins() []string {
	out := make([]string, 0, len(a.admins))
	for e := range a.admins {
		out = append(out, e)
	}
	return out
}

// Decide applies the rules to a user and the host the user asked for.
func (a *Authorizer) Decide(ctx context.Context, email, host string) (Decision, error) {
	d := Decision{Email: store.NormalizeEmail(email), Host: store.NormalizeHost(host)}
	if d.Email == "" {
		d.Reason = NoUser
		return d, nil
	}
	if a.admins[d.Email] {
		d.Allowed, d.Reason = true, Admin
		return d, nil
	}
	snap, err := a.snapshot(ctx)
	if err != nil {
		return Decision{}, err
	}
	app, ok := snap.Apps[d.Host]
	if !ok {
		d.Reason = UnknownHost
		return d, nil
	}
	d.App = app
	user, ok := snap.Users[d.Email]
	switch {
	case ok && user.Disabled:
		d.Reason = Disabled
	case ok && user.AppIDs[app.ID]:
		d.Allowed, d.Reason = true, Granted
	default:
		d.Reason = NotGranted
	}
	return d, nil
}

// Invalidate drops the cached snapshot; the next decision reloads it.
func (a *Authorizer) Invalidate() {
	a.mu.Lock()
	a.gen++
	a.cache = nil
	a.mu.Unlock()
}

// snapshot returns the cached snapshot, loading it when there is none. Loads
// are serialized so a burst of decisions after Invalidate reads the source
// once instead of once per decision.
func (a *Authorizer) snapshot(ctx context.Context) (*store.Snapshot, error) {
	if snap, _ := a.cached(); snap != nil {
		return snap, nil
	}
	a.load.Lock()
	defer a.load.Unlock()
	snap, gen := a.cached()
	if snap != nil {
		return snap, nil
	}
	loaded, err := a.source.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	if a.gen == gen {
		a.cache = &loaded
	}
	a.mu.Unlock()
	return &loaded, nil
}

func (a *Authorizer) cached() (*store.Snapshot, uint64) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cache, a.gen
}
