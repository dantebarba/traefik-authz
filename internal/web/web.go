// Package web serves the forward-auth check that Traefik calls, the admin JSON
// API and the embedded admin PWA.
//
// Every request is identified by the user header set by the forward-auth
// login in front (X-Forwarded-User by default). The API and the PWA answer
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
	"sort"
	"strconv"
	"time"

	"traefik-authz/internal/authz"
	"traefik-authz/internal/store"
)

const csrfHeader = "X-Requested-With"
const csrfValue = "traefik-authz"

// Server holds what the handlers need.
type Server struct {
	UserHeader string
	Authz      *authz.Authorizer
	Store      *store.Store
	Log        *slog.Logger
	Now        func() time.Time
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
	if d.Reason == authz.NotGranted || d.Reason == authz.Disabled {
		if err := s.Store.RecordRequest(r.Context(), d.Email, d.Host, s.Now()); err != nil {
			s.Log.Error("record access request failed", "err", err)
		}
	}
	writeForbidden(w, deniedPage(d))
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
	Me       string          `json:"me"`
	Admins   []string        `json:"admins"`
	Users    []store.User    `json:"users"`
	Apps     []store.App     `json:"apps"`
	Requests []store.Request `json:"requests"`
}

func (s *Server) state(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	st := state{Me: s.user(r), Admins: s.Authz.Admins()}
	sort.Strings(st.Admins)
	var err error
	if st.Users, err = s.Store.ListUsers(ctx); err == nil {
		if st.Apps, err = s.Store.ListApps(ctx); err == nil {
			st.Requests, err = s.Store.ListRequests(ctx)
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
