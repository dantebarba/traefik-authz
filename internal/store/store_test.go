package store

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func mustApp(t *testing.T, s *Store, host string) App {
	t.Helper()
	ctx := context.Background()
	if err := s.UpsertApp(ctx, App{Host: host, Router: "r-" + host, Name: "N " + host}, t0); err != nil {
		t.Fatal(err)
	}
	snap, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return snap.Apps[NormalizeHost(host)]
}

func TestAddUser(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	u, err := s.AddUser(ctx, "  Alice@Example.COM ", " Alice ", t0)
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != "alice@example.com" || u.Name != "Alice" || u.Disabled || !u.CreatedAt.Equal(t0) {
		t.Fatalf("user = %+v", u)
	}
	if _, err := s.AddUser(ctx, "ALICE@example.com", "", t0); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate: err = %v, want ErrExists", err)
	}
	for _, bad := range []string{"", "alice", "@example.com", "alice@", "a b@example.com", "a@b@c", "Alice <a@example.com>"} {
		if _, err := s.AddUser(ctx, bad, "", t0); !errors.Is(err, ErrInvalid) {
			t.Errorf("AddUser(%q): err = %v, want ErrInvalid", bad, err)
		}
	}
	users, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0].Email != "alice@example.com" || users[0].AppIDs == nil {
		t.Fatalf("users = %+v", users)
	}
}

func TestDisableAndDelete(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if err := s.SetDisabled(ctx, "nobody@example.com", true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetDisabled unknown: err = %v", err)
	}
	if err := s.DeleteUser(ctx, "nobody@example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteUser unknown: err = %v", err)
	}
	s.AddUser(ctx, "bob@example.com", "", t0)
	app := mustApp(t, s, "a.example.com")
	if err := s.Grant(ctx, "bob@example.com", app.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDisabled(ctx, "BOB@example.com", true); err != nil {
		t.Fatal(err)
	}
	snap, _ := s.Snapshot(ctx)
	if g := snap.Users["bob@example.com"]; !g.Disabled || !g.AppIDs[app.ID] {
		t.Fatalf("disabled user keeps grants: %+v", g)
	}
	if err := s.DeleteUser(ctx, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	s.AddUser(ctx, "bob@example.com", "", t0)
	users, _ := s.ListUsers(ctx)
	if len(users[0].AppIDs) != 0 {
		t.Fatalf("grants survived delete: %+v", users[0])
	}
}

func TestGrantRevoke(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	a := mustApp(t, s, "a.example.com")
	b := mustApp(t, s, "b.example.com")
	if err := s.Grant(ctx, "carol@example.com", a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("grant to unknown user: err = %v", err)
	}
	s.AddUser(ctx, "carol@example.com", "", t0)
	if err := s.Grant(ctx, "carol@example.com", 999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("grant unknown app: err = %v", err)
	}
	s.RecordRequest(ctx, "carol@example.com", "a.example.com", t0)
	s.RecordRequest(ctx, "carol@example.com", "b.example.com", t0)
	for range 2 {
		if err := s.Grant(ctx, "carol@example.com", a.ID); err != nil {
			t.Fatal(err)
		}
	}
	s.Grant(ctx, "carol@example.com", b.ID)
	users, _ := s.ListUsers(ctx)
	if !reflect.DeepEqual(users[0].AppIDs, []int64{a.ID, b.ID}) {
		t.Fatalf("app ids = %v", users[0].AppIDs)
	}
	requests, _ := s.ListRequests(ctx, time.Time{})
	if len(requests) != 0 {
		t.Fatalf("grant should drop the matching requests: %+v", requests)
	}
	if err := s.Revoke(ctx, "carol@example.com", a.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(ctx, "carol@example.com", a.ID); err != nil {
		t.Fatalf("revoking twice: %v", err)
	}
	users, _ = s.ListUsers(ctx)
	if !reflect.DeepEqual(users[0].AppIDs, []int64{b.ID}) {
		t.Fatalf("after revoke app ids = %v", users[0].AppIDs)
	}
}

func TestSetGrants(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	a := mustApp(t, s, "a.example.com")
	b := mustApp(t, s, "b.example.com")
	c := mustApp(t, s, "c.example.com")
	if err := s.SetGrants(ctx, "ivy@example.com", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user: err = %v", err)
	}
	s.AddUser(ctx, "ivy@example.com", "", t0)
	s.Grant(ctx, "ivy@example.com", a.ID)
	s.RecordRequest(ctx, "ivy@example.com", "b.example.com", t0)
	s.RecordRequest(ctx, "ivy@example.com", "c.example.com", t0)
	if err := s.SetGrants(ctx, "IVY@example.com", []int64{b.ID, b.ID}); err != nil {
		t.Fatal(err)
	}
	users, _ := s.ListUsers(ctx)
	if !reflect.DeepEqual(users[0].AppIDs, []int64{b.ID}) {
		t.Fatalf("app ids = %v, want [%d]", users[0].AppIDs, b.ID)
	}
	requests, _ := s.ListRequests(ctx, time.Time{})
	if len(requests) != 1 || requests[0].Host != "c.example.com" {
		t.Fatalf("requests = %+v, want only the one for c", requests)
	}
	if err := s.SetGrants(ctx, "ivy@example.com", []int64{a.ID, 999}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown app: err = %v", err)
	}
	users, _ = s.ListUsers(ctx)
	if !reflect.DeepEqual(users[0].AppIDs, []int64{b.ID}) {
		t.Fatalf("failed call changed grants: %v", users[0].AppIDs)
	}
	if err := s.SetGrants(ctx, "ivy@example.com", []int64{a.ID, b.ID, c.ID}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGrants(ctx, "ivy@example.com", []int64{}); err != nil {
		t.Fatal(err)
	}
	users, _ = s.ListUsers(ctx)
	if len(users[0].AppIDs) != 0 {
		t.Fatalf("revoke all left %v", users[0].AppIDs)
	}
}

func TestUpsertAppKeepsIDAndGrants(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	first := mustApp(t, s, "App.Example.com:443")
	if first.Host != "app.example.com" {
		t.Fatalf("host not normalized: %q", first.Host)
	}
	s.AddUser(ctx, "dan@example.com", "", t0)
	s.Grant(ctx, "dan@example.com", first.ID)
	later := t0.Add(time.Hour)
	if err := s.UpsertApp(ctx, App{Host: "app.example.com", Router: "renamed", Name: "Renamed", Icon: "🔒"}, later); err != nil {
		t.Fatal(err)
	}
	apps, _ := s.ListApps(ctx)
	want := App{ID: first.ID, Host: "app.example.com", Router: "renamed", Name: "Renamed", Icon: "🔒", LastSeen: later}
	if len(apps) != 1 || !reflect.DeepEqual(apps[0], want) {
		t.Fatalf("apps = %+v, want %+v", apps, want)
	}
	snap, _ := s.Snapshot(ctx)
	if !snap.Users["dan@example.com"].AppIDs[first.ID] {
		t.Fatal("grant lost on upsert")
	}
	if err := s.UpsertApp(ctx, App{Host: " "}, t0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty host: err = %v", err)
	}
}

func TestRequests(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	mustApp(t, s, "a.example.com")
	s.RecordRequest(ctx, "Eve@example.com", "A.example.com", t0)
	s.RecordRequest(ctx, "eve@example.com", "a.example.com", t0.Add(time.Minute))
	s.RecordRequest(ctx, "fay@example.com", "a.example.com", t0)
	requests, err := s.ListRequests(ctx, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	want := []Request{
		{Email: "eve@example.com", Host: "a.example.com", RequestedAt: t0.Add(time.Minute)},
		{Email: "fay@example.com", Host: "a.example.com", RequestedAt: t0},
	}
	if !reflect.DeepEqual(requests, want) {
		t.Fatalf("requests = %+v, want %+v", requests, want)
	}
	if err := s.DismissRequest(ctx, "fay@example.com", "a.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.DismissRequest(ctx, "fay@example.com", "a.example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("dismiss twice: err = %v", err)
	}
	if err := s.ApproveRequest(ctx, "eve@example.com", "unknown.example.com", t0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("approve unknown host: err = %v", err)
	}
	if err := s.ApproveRequest(ctx, "eve@example.com", "a.example.com", t0); err != nil {
		t.Fatal(err)
	}
	requests, _ = s.ListRequests(ctx, time.Time{})
	users, _ := s.ListUsers(ctx)
	if len(requests) != 0 || len(users) != 1 || users[0].Email != "eve@example.com" || len(users[0].AppIDs) != 1 {
		t.Fatalf("after approve: requests %+v, users %+v", requests, users)
	}
}

func TestRequestExpiry(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	s.RecordRequest(ctx, "old@example.com", "a.example.com", t0)
	s.RecordRequest(ctx, "new@example.com", "a.example.com", t0.Add(48*time.Hour))
	cut := t0.Add(24 * time.Hour)
	requests, _ := s.ListRequests(ctx, cut)
	if len(requests) != 1 || requests[0].Email != "new@example.com" {
		t.Fatalf("since cut: %+v", requests)
	}
	if _, ok, _ := s.PendingRequest(ctx, "OLD@example.com", "a.example.com", cut); ok {
		t.Fatal("expired request reported pending")
	}
	if at, ok, err := s.PendingRequest(ctx, "old@example.com", "A.example.com", time.Time{}); err != nil || !ok || !at.Equal(t0) {
		t.Fatalf("PendingRequest without cut = %v, %v, %v", at, ok, err)
	}
	if _, ok, _ := s.PendingRequest(ctx, "nobody@example.com", "a.example.com", time.Time{}); ok {
		t.Fatal("missing request reported pending")
	}
	s.RecordRequest(ctx, "old@example.com", "a.example.com", t0.Add(48*time.Hour))
	if _, ok, _ := s.PendingRequest(ctx, "old@example.com", "a.example.com", cut); !ok {
		t.Fatal("asking again does not renew an expired request")
	}
}

func TestApproveKeepsDisabledUserDisabled(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	app := mustApp(t, s, "a.example.com")
	s.AddUser(ctx, "gus@example.com", "Gus", t0)
	s.SetDisabled(ctx, "gus@example.com", true)
	if err := s.ApproveRequest(ctx, "gus@example.com", "a.example.com", t0); err != nil {
		t.Fatal(err)
	}
	snap, _ := s.Snapshot(ctx)
	if g := snap.Users["gus@example.com"]; !g.Disabled || !g.AppIDs[app.ID] {
		t.Fatalf("grantee = %+v", g)
	}
}

func TestFileDatabasePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "authz.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s.AddUser(ctx, "hal@example.com", "", t0)
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	users, _ := s.ListUsers(ctx)
	if len(users) != 1 {
		t.Fatalf("users after reopen = %+v", users)
	}
}

func TestNormalizeHost(t *testing.T) {
	for in, want := range map[string]string{
		"Example.COM":        "example.com",
		"example.com:8443":   "example.com",
		" example.com. ":     "example.com",
		"[2001:db8::1]:443":  "2001:db8::1",
		"sub.example.com:80": "sub.example.com",
	} {
		if got := NormalizeHost(in); got != want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}
