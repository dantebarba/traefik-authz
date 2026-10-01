// Package web serves the forward-auth check that Traefik calls, the admin JSON
// API and the embedded admin PWA.
//
// Every request is identified by the user header set by the forward-auth
// login in front (X-Forwarded-User by default). A denied visit records
// nothing: the 403 page offers a "Request access" button that posts to
// RequestAccessPath on the same host, which Traefik sends through /check
// like any other request, and only that post records an access request. The API and the PWA answer
// only admins; state-changing API calls must also carry
// "X-Requested-With: traefik-authz", which a cross-site form cannot send.
package web

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"traefik-authz/internal/authz"
	"traefik-authz/internal/store"
)

const csrfHeader = "X-Requested-With"
const csrfValue = "traefik-authz"

// RequestAccessPath is the path, on any protected host, that the 403 page's
// "Request access" button posts to.
const RequestAccessPath = "/.traefik-authz/request-access"

// Server holds what the handlers need.
type Server struct {
	UserHeader    string
	RequestExpiry time.Duration
	Authz         *authz.Authorizer
	Store         *store.Store
	Log           *slog.Logger
	Now           func() time.Time
}

// Handler returns the routes: /check, /healthz, /api/ and the PWA at /.
func (s *Server) Handler() http.Handler {
	static, err := fs.Sub(Static, "static")
	if err != nil {
		panic(err)
	}
	api := http.NewServeMux()
	api.HandleFunc("GET /api/state", s.state)
	api.HandleFunc("POST /api/users", s.addUser)
	api.HandleFunc("PATCH /api/users/{email}", s.updateUser)
	api.HandleFunc("DELETE /api/users/{email}", s.deleteUser)
	api.HandleFunc("PUT /api/users/{email}/apps/{id}", s.grant)
	api.HandleFunc("DELETE /api/users/{email}/apps/{id}", s.revoke)
	api.HandleFunc("PUT /api/users/{email}/apps", s.setGrants)
	api.HandleFunc("GET /api/apps/{id}/icon", s.favicon)
	api.HandleFunc("POST /api/requests/approve", s.approve)
	api.HandleFunc("POST /api/requests/dismiss", s.dismiss)

	mux := http.NewServeMux()
	mux.HandleFunc("/check", s.check)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.Handle("/api/", s.adminOnly(s.sameSite(api)))
	mux.Handle("/", s.adminOnly(panelHeaders(http.FileServerFS(static))))
	return mux
}

func (s *Server) user(r *http.Request) string {
	return store.NormalizeEmail(r.Header.Get(s.UserHeader))
}

func (s *Server) check(w http.ResponseWriter, r *http.Request) {
	d, err := s.Authz.Decide(r.Context(), s.user(r), r.Header.Get("X-Forwarded-Host"))
	if err != nil {
		s.Log.Error("check failed", "err", err)
		http.Error(w, "authorization unavailable", http.StatusInternalServerError)
		return
	}
	if d.Allowed {
		s.Log.Debug("allowed", "user", d.Email, "host", d.Host, "reason", d.Reason)
		w.WriteHeader(http.StatusOK)
		return
	}
	s.Log.Info("denied", "user", d.Email, "host", d.Host, "reason", d.Reason)
	uri, err := url.ParseRequestURI(r.Header.Get("X-Forwarded-Uri"))
	if err != nil {
		uri = &url.URL{Path: "/"}
	}
	if d.Reason == authz.NotGranted && uri.Path == RequestAccessPath && r.Header.Get("X-Forwarded-Method") == http.MethodPost {
		s.requestAccess(w, r, d, uri)
		return
	}
	writeForbidden(w, s.deniedPage(r.Context(), d, uri))
}

func (s *Server) requestAccess(w http.ResponseWriter, r *http.Request, d authz.Decision, uri *url.URL) {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		s.Log.Warn("cross-site access request refused", "user", d.Email, "host", d.Host, "site", site)
		writeForbidden(w, page{Title: "Request not sent", Detail: "Access can only be requested from this site's own page.", Email: d.Email})
		return
	}
	if err := s.Store.RecordRequest(r.Context(), d.Email, d.Host, s.Now()); err != nil {
		s.Log.Error("record access request failed", "err", err)
		http.Error(w, "could not record the request", http.StatusInternalServerError)
		return
	}
	s.Log.Info("access requested", "user", d.Email, "host", d.Host)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Location", backTo(r, returnPath(uri.Query().Get("return"))))
	w.WriteHeader(http.StatusSeeOther)
}

// backTo makes path absolute on the host the user asked for. Traefik resolves
// a relative Location from an auth server against the auth server's own
// address, which would send the browser to an internal host name.
func backTo(r *http.Request, path string) string {
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme != "http" {
		scheme = "https"
	}
	host := r.Header.Get("X-Forwarded-Host")
	if u, err := url.Parse(scheme + "://" + host); err != nil || u.Host != host || host == "" {
		return path
	}
	return scheme + "://" + host + path
}

// returnPath keeps a post-request redirect on the same host: only an absolute
// path is accepted, and anything else, including //host, becomes "/".
func returnPath(p string) string {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") || strings.HasPrefix(p, RequestAccessPath) {
		return "/"
	}
	return p
}

// requestCutoff is the oldest time a pending request may have, or zero when
// requests never expire.
func (s *Server) requestCutoff() time.Time {
	if s.RequestExpiry <= 0 {
		return time.Time{}
	}
	return s.Now().Add(-s.RequestExpiry)
}

func (s *Server) adminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email := s.user(r)
		if !s.Authz.IsAdmin(email) {
			writeForbidden(w, panelDeniedPage(email))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) sameSite(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get(csrfHeader) != csrfValue {
			writeError(w, http.StatusForbidden, "missing "+csrfHeader+" header")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func panelHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-cache")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

type state struct {
	Me                string          `json:"me"`
	RequestExpiryDays int             `json:"request_expiry_days"`
	Admins            []string        `json:"admins"`
	Users             []store.User    `json:"users"`
	Apps              []store.App     `json:"apps"`
	Requests          []store.Request `json:"requests"`
}

func (s *Server) state(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	st := state{Me: s.user(r), Admins: s.Authz.Admins(), RequestExpiryDays: int(s.RequestExpiry / (24 * time.Hour))}
	sort.Strings(st.Admins)
	var err error
	if st.Users, err = s.Store.ListUsers(ctx); err == nil {
		if st.Apps, err = s.Store.ListApps(ctx); err == nil {
			st.Requests, err = s.Store.ListRequests(ctx, s.requestCutoff())
		}
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) addUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	u, err := s.Store.AddUser(r.Context(), body.Email, body.Name, s.Now())
	if err != nil {
		s.fail(w, err)
		return
	}
	s.Authz.Invalidate()
	writeJSON(w, http.StatusCreated, u)
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Disabled *bool `json:"disabled"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.Disabled == nil {
		writeError(w, http.StatusBadRequest, "nothing to update: send {\"disabled\": true|false}")
		return
	}
	s.mutate(w, r, func(ctx context.Context) error {
		return s.Store.SetDisabled(ctx, r.PathValue("email"), *body.Disabled)
	})
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	s.mutate(w, r, func(ctx context.Context) error {
		return s.Store.DeleteUser(ctx, r.PathValue("email"))
	})
}

func (s *Server) grant(w http.ResponseWriter, r *http.Request) {
	id, ok := appID(w, r)
	if !ok {
		return
	}
	s.mutate(w, r, func(ctx context.Context) error {
		return s.Store.Grant(ctx, r.PathValue("email"), id)
	})
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	id, ok := appID(w, r)
	if !ok {
		return
	}
	s.mutate(w, r, func(ctx context.Context) error {
		return s.Store.Revoke(ctx, r.PathValue("email"), id)
	})
}

func (s *Server) setGrants(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AppIDs *[]int64 `json:"app_ids"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.AppIDs == nil {
		writeError(w, http.StatusBadRequest, "send {\"app_ids\": [...]}, empty to revoke everything")
		return
	}
	s.mutate(w, r, func(ctx context.Context) error {
		return s.Store.SetGrants(ctx, r.PathValue("email"), *body.AppIDs)
	})
}

func (s *Server) favicon(w http.ResponseWriter, r *http.Request) {
	id, ok := appID(w, r)
	if !ok {
		return
	}
	contentType, data, err := s.Store.Favicon(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "private, max-age=86400")
	w.Write(data)
}

type requestKey struct {
	Email string `json:"email"`
	Host  string `json:"host"`
}

func (s *Server) approve(w http.ResponseWriter, r *http.Request) {
	var body requestKey
	if !readJSON(w, r, &body) {
		return
	}
	s.mutate(w, r, func(ctx context.Context) error {
		return s.Store.ApproveRequest(ctx, body.Email, body.Host, s.Now())
	})
}

func (s *Server) dismiss(w http.ResponseWriter, r *http.Request) {
	var body requestKey
	if !readJSON(w, r, &body) {
		return
	}
	s.mutate(w, r, func(ctx context.Context) error {
		return s.Store.DismissRequest(ctx, body.Email, body.Host)
	})
}

func (s *Server) mutate(w http.ResponseWriter, r *http.Request, fn func(context.Context) error) {
	if err := fn(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	s.Authz.Invalidate()
	w.WriteHeader(http.StatusNoContent)
}

func appID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "app id must be a number")
		return 0, false
	}
	return id, true
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, store.ErrExists):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, store.ErrInvalid):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		s.Log.Error("api failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
