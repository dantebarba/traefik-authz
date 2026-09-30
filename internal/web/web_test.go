package web

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"traefik-authz/internal/authz"
	"traefik-authz/internal/store"
)

const admin = "admin@example.com"

type env struct {
	t     *testing.T
	store *store.Store
	h     http.Handler
	app   store.App
}

func setup(t *testing.T) *env {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()
	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	if err := db.UpsertApp(ctx, store.App{Host: "whoami.example.com", Router: "whoami", Name: "whoami"}, now); err != nil {
		t.Fatal(err)
	}
	apps, _ := db.ListApps(ctx)
	s := &Server{
		UserHeader: "X-Forwarded-User",
		Authz:      authz.New([]string{admin}, db),
		Store:      db,
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:        func() time.Time { return now },
	}
	return &env{t: t, store: db, h: s.Handler(), app: apps[0]}
}

func (e *env) check(user, host string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/check", nil)
	if user != "" {
		req.Header.Set("X-Forwarded-User", user)
	}
	if host != "" {
		req.Header.Set("X-Forwarded-Host", host)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func (e *env) call(user, method, path, body string, csrf bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if user != "" {
		req.Header.Set("X-Forwarded-User", user)
	}
	if csrf {
		req.Header.Set("X-Requested-With", "traefik-authz")
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func (e *env) mustCall(method, path, body string, want int) *httptest.ResponseRecorder {
	e.t.Helper()
	rec := e.call(admin, method, path, body, true)
	if rec.Code != want {
		e.t.Fatalf("%s %s = %d %s, want %d", method, path, rec.Code, rec.Body, want)
	}
	return rec
}

func TestCheckMatrix(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	e.store.AddUser(ctx, "granted@example.com", "", time.Now())
	e.store.Grant(ctx, "granted@example.com", e.app.ID)
	e.store.AddUser(ctx, "disabled@example.com", "", time.Now())
	e.store.Grant(ctx, "disabled@example.com", e.app.ID)
	e.store.SetDisabled(ctx, "disabled@example.com", true)
	e.store.AddUser(ctx, "nogrant@example.com", "", time.Now())

	cases := []struct {
		name, user, host string
		code             int
		body             string
	}{
		{"no user header", "", "whoami.example.com", 403, "Not signed in"},
		{"admin", admin, "whoami.example.com", 200, ""},
		{"admin on unknown host", admin, "unknown.example.com", 200, ""},
		{"unknown host", "granted@example.com", "unknown.example.com", 403, "Access denied"},
		{"granted", "granted@example.com", "whoami.example.com", 200, ""},
		{"granted, host with port", "Granted@example.com", "whoami.example.com:443", 200, ""},
		{"without grant", "nogrant@example.com", "whoami.example.com", 403, "have access to whoami"},
		{"unknown user", "stranger@example.com", "whoami.example.com", 403, "have access to whoami"},
		{"disabled", "disabled@example.com", "whoami.example.com", 403, "Account disabled"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := e.check(c.user, c.host)
			if rec.Code != c.code || !strings.Contains(rec.Body.String(), c.body) {
				t.Fatalf("code %d body %q, want %d containing %q", rec.Code, rec.Body, c.code, c.body)
			}
			if c.code == 403 && !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
				t.Fatalf("403 is not an HTML page: %q", rec.Header().Get("Content-Type"))
			}
		})
	}

	requests, _ := e.store.ListRequests(ctx)
	got := map[string]bool{}
	for _, r := range requests {
		got[r.Email+" "+r.Host] = true
	}
	want := map[string]bool{"nogrant@example.com whoami.example.com": true, "stranger@example.com whoami.example.com": true, "disabled@example.com whoami.example.com": true}
	if len(got) != len(want) || !got["nogrant@example.com whoami.example.com"] || !got["stranger@example.com whoami.example.com"] || !got["disabled@example.com whoami.example.com"] {
		t.Fatalf("recorded requests = %v, want %v", got, want)
	}
}

func TestCheckEscapesPage(t *testing.T) {
	e := setup(t)
	rec := e.check("<script>@example.com", "whoami.example.com")
	if strings.Contains(rec.Body.String(), "<script>") {
		t.Fatalf("user header not escaped: %s", rec.Body)
	}
}

func TestPanelFlow(t *testing.T) {
	e := setup(t)
	path := "/api/users/pat@example.com/apps/" + itoa(e.app.ID)

	e.mustCall("POST", "/api/users", `{"email":"Pat@Example.com","name":"Pat"}`, 201)
	e.mustCall("POST", "/api/users", `{"email":"pat@example.com"}`, 409)
	e.mustCall("POST", "/api/users", `{"email":"not-an-email"}`, 400)
	if rec := e.check("pat@example.com", "whoami.example.com"); rec.Code != 403 {
		t.Fatalf("before grant: %d", rec.Code)
	}
	e.mustCall("PUT", path, "", 204)
	if rec := e.check("pat@example.com", "whoami.example.com"); rec.Code != 200 {
		t.Fatalf("after grant: %d", rec.Code)
	}
	e.mustCall("PATCH", "/api/users/pat@example.com", `{"disabled":true}`, 204)
	if rec := e.check("pat@example.com", "whoami.example.com"); rec.Code != 403 {
		t.Fatalf("after disable: %d", rec.Code)
	}
	e.mustCall("PATCH", "/api/users/pat@example.com", `{"disabled":false}`, 204)
	e.mustCall("PATCH", "/api/users/pat@example.com", `{}`, 400)
	e.mustCall("DELETE", path, "", 204)
	if rec := e.check("pat@example.com", "whoami.example.com"); rec.Code != 403 {
		t.Fatalf("after revoke: %d", rec.Code)
	}
	e.mustCall("PUT", "/api/users/pat@example.com/apps/999", "", 404)
	e.mustCall("PUT", "/api/users/pat@example.com/apps/x", "", 400)
	e.mustCall("DELETE", "/api/users/pat@example.com", "", 204)
	e.mustCall("DELETE", "/api/users/pat@example.com", "", 404)
}

func TestApproveAndDismissRequests(t *testing.T) {
	e := setup(t)
	e.check("quinn@example.com", "whoami.example.com")
	e.check("rae@example.com", "whoami.example.com")

	var st state
	json.Unmarshal(e.mustCall("GET", "/api/state", "", 200).Body.Bytes(), &st)
	if st.Me != admin || len(st.Requests) != 2 || len(st.Apps) != 1 || len(st.Admins) != 1 {
		t.Fatalf("state = %+v", st)
	}

	e.mustCall("POST", "/api/requests/approve", `{"email":"quinn@example.com","host":"whoami.example.com"}`, 204)
	if rec := e.check("quinn@example.com", "whoami.example.com"); rec.Code != 200 {
		t.Fatalf("approved user: %d", rec.Code)
	}
	e.mustCall("POST", "/api/requests/dismiss", `{"email":"rae@example.com","host":"whoami.example.com"}`, 204)
	e.mustCall("POST", "/api/requests/dismiss", `{"email":"rae@example.com","host":"whoami.example.com"}`, 404)
	e.mustCall("POST", "/api/requests/approve", `{"email":"rae@example.com","host":"gone.example.com"}`, 404)
	e.mustCall("POST", "/api/requests/approve", `{"email":"rae@example.com","host":"whoami.example.com","extra":1}`, 400)

	json.Unmarshal(e.mustCall("GET", "/api/state", "", 200).Body.Bytes(), &st)
	if len(st.Requests) != 0 || len(st.Users) != 1 || st.Users[0].Email != "quinn@example.com" {
		t.Fatalf("state after = %+v", st)
	}
}

func TestAPIOnlyForAdmins(t *testing.T) {
	e := setup(t)
	for _, user := range []string{"", "someone@example.com"} {
		if rec := e.call(user, "GET", "/api/state", "", true); rec.Code != 403 {
			t.Errorf("GET /api/state as %q = %d", user, rec.Code)
		}
		if rec := e.call(user, "POST", "/api/users", `{"email":"x@example.com"}`, true); rec.Code != 403 {
			t.Errorf("POST /api/users as %q = %d", user, rec.Code)
		}
	}
	if users, _ := e.store.ListUsers(context.Background()); len(users) != 0 {
		t.Fatalf("non-admin created users: %+v", users)
	}
}

func TestAPIMutationsNeedCSRFHeader(t *testing.T) {
	e := setup(t)
	if rec := e.call(admin, "POST", "/api/users", `{"email":"x@example.com"}`, false); rec.Code != 403 {
		t.Fatalf("POST without header = %d", rec.Code)
	}
	if rec := e.call(admin, "GET", "/api/state", "", false); rec.Code != 200 {
		t.Fatalf("GET without header = %d", rec.Code)
	}
}

func TestPanelAssets(t *testing.T) {
	e := setup(t)
	for _, path := range []string{"/", "/styles.css", "/app.js", "/sw.js", "/manifest.webmanifest", "/icons/icon-192.png"} {
		rec := e.call(admin, "GET", path, "", false)
		if rec.Code != 200 {
			t.Errorf("GET %s as admin = %d", path, rec.Code)
		}
		if rec.Header().Get("Content-Security-Policy") == "" {
			t.Errorf("GET %s has no CSP", path)
		}
		if rec := e.call("someone@example.com", "GET", path, "", false); rec.Code != 403 {
			t.Errorf("GET %s as non-admin = %d", path, rec.Code)
		}
	}
	if rec := e.call(admin, "GET", "/", "", false); !strings.Contains(rec.Body.String(), "manifest.webmanifest") {
		t.Fatal("index does not link the manifest")
	}
}

func TestHealthz(t *testing.T) {
	e := setup(t)
	if rec := e.call("", "GET", "/healthz", "", false); rec.Code != 200 {
		t.Fatalf("healthz = %d", rec.Code)
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
