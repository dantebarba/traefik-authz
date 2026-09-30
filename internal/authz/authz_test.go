package authz

import (
	"context"
	"errors"
	"testing"

	"traefik-authz/internal/store"
)

type fakeSource struct {
	snap  store.Snapshot
	err   error
	loads int
}

func (f *fakeSource) Snapshot(context.Context) (store.Snapshot, error) {
	f.loads++
	return f.snap, f.err
}

func fixture() *fakeSource {
	return &fakeSource{snap: store.Snapshot{
		Apps: map[string]store.App{
			"whoami.example.com": {ID: 1, Host: "whoami.example.com", Name: "whoami"},
			"logs.example.com":   {ID: 2, Host: "logs.example.com", Name: "logs"},
		},
		Users: map[string]store.Grantee{
			"granted@example.com":  {AppIDs: map[int64]bool{1: true}},
			"disabled@example.com": {Disabled: true, AppIDs: map[int64]bool{1: true}},
			"nogrant@example.com":  {AppIDs: map[int64]bool{}},
		},
	}}
}

func TestDecide(t *testing.T) {
	a := New([]string{" Admin@Example.com "}, fixture())
	cases := []struct {
		name, user, host string
		allowed          bool
		reason           Reason
	}{
		{"no user header", "", "whoami.example.com", false, NoUser},
		{"admin on a known host", "admin@example.com", "whoami.example.com", true, Admin},
		{"admin on an unknown host", "ADMIN@example.com", "other.example.com", true, Admin},
		{"unknown host", "granted@example.com", "other.example.com", false, UnknownHost},
		{"no host", "granted@example.com", "", false, UnknownHost},
		{"granted", "Granted@Example.com", "whoami.example.com", true, Granted},
		{"granted, host with port and case", "granted@example.com", "WHOAMI.example.com:443", true, Granted},
		{"granted another app only", "granted@example.com", "logs.example.com", false, NotGranted},
		{"user without grants", "nogrant@example.com", "whoami.example.com", false, NotGranted},
		{"unknown user", "stranger@example.com", "whoami.example.com", false, NotGranted},
		{"disabled user with grant", "disabled@example.com", "whoami.example.com", false, Disabled},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := a.Decide(context.Background(), c.user, c.host)
			if err != nil {
				t.Fatal(err)
			}
			if d.Allowed != c.allowed || d.Reason != c.reason {
				t.Fatalf("Decide(%q, %q) = %v/%s, want %v/%s", c.user, c.host, d.Allowed, d.Reason, c.allowed, c.reason)
			}
		})
	}
}

func TestDecideCachesUntilInvalidate(t *testing.T) {
	src := fixture()
	a := New([]string{"admin@example.com"}, src)
	ctx := context.Background()
	a.Decide(ctx, "nogrant@example.com", "whoami.example.com")
	src.snap = fixture().snap
	src.snap.Users["nogrant@example.com"] = store.Grantee{AppIDs: map[int64]bool{1: true}}
	if d, _ := a.Decide(ctx, "nogrant@example.com", "whoami.example.com"); d.Allowed {
		t.Fatal("cache not used")
	}
	if src.loads != 1 {
		t.Fatalf("loads = %d, want 1", src.loads)
	}
	a.Invalidate()
	if d, _ := a.Decide(ctx, "nogrant@example.com", "whoami.example.com"); !d.Allowed {
		t.Fatal("grant not seen after Invalidate")
	}
	if src.loads != 2 {
		t.Fatalf("loads = %d, want 2", src.loads)
	}
}

func TestDecideAdminNeedsNoSource(t *testing.T) {
	src := &fakeSource{err: errors.New("database down")}
	a := New([]string{"admin@example.com"}, src)
	if d, err := a.Decide(context.Background(), "admin@example.com", "x.example.com"); err != nil || !d.Allowed {
		t.Fatalf("admin: %+v, %v", d, err)
	}
	if _, err := a.Decide(context.Background(), "user@example.com", "x.example.com"); err == nil {
		t.Fatal("source error not reported")
	}
}
