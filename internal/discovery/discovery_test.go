package discovery

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"traefik-authz/internal/store"
)

func TestHostsFromRule(t *testing.T) {
	cases := map[string][]string{
		"Host(`whoami.example.com`)":                                        {"whoami.example.com"},
		"Host(`A.example.com`) || Host(`b.example.com`)":                    {"a.example.com", "b.example.com"},
		"Host(`a.example.com`, `b.example.com`)":                            {"a.example.com", "b.example.com"},
		"Host(\"a.example.com\") && PathPrefix(`/app`)":                     {"a.example.com"},
		"(Host(`a.example.com`) || Host(`a.example.com`)) && Method(`GET`)": {"a.example.com"},
		"HostRegexp(`{sub:[a-z]+}.example.com`)":                            nil,
		"HostSNI(`a.example.com`)":                                          nil,
		"PathPrefix(`/`)":                                                   nil,
		"":                                                                  nil,
		"Host(`a.example.com`) || HostRegexp(`.+`)":                         {"a.example.com"},
	}
	for rule, want := range cases {
		if got := HostsFromRule(rule); !reflect.DeepEqual(got, want) {
			t.Errorf("HostsFromRule(%q) = %q, want %q", rule, got, want)
		}
	}
}

func TestUsesMiddleware(t *testing.T) {
	cases := map[string]bool{
		"traefik-authz":        true,
		"traefik-authz@docker": true,
		"tls-headers, traefik-forward-auth ,traefik-authz":      true,
		"tls-headers,traefik-forward-auth,traefik-authz@docker": true,
		"traefik-authz-other":                                   false,
		"traefik-authz@file":                                    false,
		"traefik-forward-auth":                                  false,
		"":                                                      false,
	}
	for value, want := range cases {
		if got := UsesMiddleware(value, "traefik-authz"); got != want {
			t.Errorf("UsesMiddleware(%q) = %v, want %v", value, got, want)
		}
	}
}

func TestAppsFromLabelsIgnoresKeyCase(t *testing.T) {
	labels := map[string]string{
		"Traefik.HTTP.Routers.Mixed.Rule":        "Host(`mixed.example.com`)",
		"traefik.http.routers.Mixed.Middlewares": "traefik-authz",
		"Traefik-Authz.Name":                     "Mixed",
	}
	got := AppsFromLabels(labels, "traefik-authz")
	want := []store.App{{Host: "mixed.example.com", Router: "Mixed", Name: "Mixed"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("apps = %+v\nwant %+v", got, want)
	}
}

func TestAppsFromLabels(t *testing.T) {
	labels := map[string]string{
		"traefik.enable":                                             "true",
		"traefik.http.routers.whoami.rule":                           "Host(`whoami.example.com`) || Host(`who.example.com`)",
		"traefik.http.routers.whoami.middlewares":                    "tls-headers,traefik-forward-auth,traefik-authz",
		"traefik.http.routers.open.rule":                             "Host(`open.example.com`)",
		"traefik.http.routers.open.middlewares":                      "tls-headers",
		"traefik.http.routers.api.rule":                              "Host(`api.example.com`)",
		"traefik.http.routers.api.middlewares":                       "traefik-authz@docker",
		"traefik.http.routers.norule.middlewares":                    "traefik-authz",
		"traefik.http.middlewares.traefik-authz.forwardauth.address": "http://traefik-authz:8080/check",
		"traefik-authz.icon":                                         "🔒",
	}
	got := AppsFromLabels(labels, "traefik-authz")
	want := []store.App{
		{Host: "api.example.com", Router: "api", Name: "api", Icon: "🔒"},
		{Host: "who.example.com", Router: "whoami", Name: "whoami", Icon: "🔒"},
		{Host: "whoami.example.com", Router: "whoami", Name: "whoami", Icon: "🔒"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("apps = %+v\nwant %+v", got, want)
	}

	labels["traefik-authz.name"] = "Who Am I"
	if got := AppsFromLabels(labels, "traefik-authz"); got[0].Name != "Who Am I" {
		t.Fatalf("name label ignored: %+v", got[0])
	}
	labels["traefik.enable"] = "False"
	if got := AppsFromLabels(labels, "traefik-authz"); len(got) != 0 {
		t.Fatalf("disabled container yields %+v", got)
	}
	if got := AppsFromLabels(nil, "traefik-authz"); len(got) != 0 {
		t.Fatalf("no labels yields %+v", got)
	}
}

type fakeEngine struct {
	containers []Container
	err        error
}

func (f *fakeEngine) Containers(context.Context) ([]Container, error) { return f.containers, f.err }

func (f *fakeEngine) Events(ctx context.Context, _ func()) error {
	<-ctx.Done()
	return ctx.Err()
}

type fakeSink struct {
	apps []store.App
	seen []time.Time
}

func (f *fakeSink) UpsertApp(_ context.Context, a store.App, seen time.Time) error {
	f.apps = append(f.apps, a)
	f.seen = append(f.seen, seen)
	return nil
}

func TestWatcherSync(t *testing.T) {
	now := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	engine := &fakeEngine{containers: []Container{
		{ID: "a", Labels: map[string]string{
			"traefik.http.routers.a.rule":        "Host(`a.example.com`)",
			"traefik.http.routers.a.middlewares": "traefik-authz",
		}},
		{ID: "b", Labels: map[string]string{"traefik.http.routers.b.rule": "Host(`b.example.com`)"}},
	}}
	sink := &fakeSink{}
	changes := 0
	w := &Watcher{Engine: engine, Sink: sink, Middleware: "traefik-authz", OnChange: func() { changes++ }, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return now }}
	n, err := w.Sync(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("Sync = %d, %v", n, err)
	}
	if len(sink.apps) != 1 || sink.apps[0].Host != "a.example.com" || !sink.seen[0].Equal(now) || changes != 1 {
		t.Fatalf("sink = %+v, changes = %d", sink, changes)
	}
	engine.err = fmt.Errorf("docker down")
	if _, err := w.Sync(context.Background()); err == nil {
		t.Fatal("engine error not reported")
	}
}

func fakeDocker(t *testing.T, handler http.Handler) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "docker.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	srv := &http.Server{Handler: handler}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return "unix://" + socket
}

func TestDockerOverUnixSocket(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /containers/json", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `[{"Id":"abc","Names":["/whoami"],"Labels":{"traefik.http.routers.w.rule":"Host(`+"`w.example.com`"+`)"}}]`)
	})
	mux.HandleFunc("GET /events", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("filters"); got != `{"type":["container"],"event":["start"]}` {
			http.Error(w, "bad filters "+got, http.StatusBadRequest)
			return
		}
		io.WriteString(w, `{"Type":"container","Action":"start"}`+"\n")
		io.WriteString(w, `{"Type":"container","Action":"exec_start: sh"}`+"\n")
		io.WriteString(w, `{"Type":"network","Action":"connect"}`+"\n")
	})
	d, err := NewDocker(fakeDocker(t, mux))
	if err != nil {
		t.Fatal(err)
	}
	containers, err := d.Containers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(containers) != 1 || containers[0].ID != "abc" || containers[0].Labels["traefik.http.routers.w.rule"] != "Host(`w.example.com`)" {
		t.Fatalf("containers = %+v", containers)
	}
	started := 0
	err = d.Events(context.Background(), func() { started++ })
	if err == nil || started != 1 {
		t.Fatalf("Events: started = %d, err = %v", started, err)
	}
}

func TestNewDockerRejectsUnknownScheme(t *testing.T) {
	if _, err := NewDocker("ssh://host"); err == nil {
		t.Fatal("ssh:// accepted")
	}
	if _, err := NewDocker("tcp://docker-proxy:2375"); err != nil {
		t.Fatal(err)
	}
}
