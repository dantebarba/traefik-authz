package discovery

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync"
	"testing"
	"time"

	"traefik-authz/internal/store"
)

var png = []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")

func container(t *testing.T, raw string) Container {
	t.Helper()
	var c Container
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestOrigins(t *testing.T) {
	cases := []struct {
		name, raw, router string
		want              []string
	}{
		{"service port label", `{"Labels":{"traefik.http.services.web.loadbalancer.server.port":"8080"},"NetworkSettings":{"Networks":{"main":{"IPAddress":"192.0.2.11"},"other":{"IPAddress":"198.51.100.11"}}}}`, "web",
			[]string{"http://192.0.2.11:8080", "http://198.51.100.11:8080"}},
		{"router names its service", `{"Labels":{"traefik.http.routers.r.service":"api@docker","traefik.http.services.api.loadbalancer.server.port":"9000","traefik.http.services.api.loadbalancer.server.scheme":"https","traefik.http.services.ui.loadbalancer.server.port":"80"},"NetworkSettings":{"Networks":{"main":{"IPAddress":"192.0.2.12"}}}}`, "r",
			[]string{"https://192.0.2.12:9000"}},
		{"only exposed port", `{"Ports":[{"PrivatePort":3000,"Type":"tcp"},{"PrivatePort":3000,"Type":"tcp"},{"PrivatePort":53,"Type":"udp"}],"NetworkSettings":{"Networks":{"main":{"IPAddress":"192.0.2.13"}}}}`, "r",
			[]string{"http://192.0.2.13:3000"}},
		{"two exposed ports, no label", `{"Ports":[{"PrivatePort":80,"Type":"tcp"},{"PrivatePort":443,"Type":"tcp"}],"NetworkSettings":{"Networks":{"main":{"IPAddress":"192.0.2.14"}}}}`, "r", nil},
		{"no network address", `{"Labels":{"traefik.http.services.web.loadbalancer.server.port":"80"},"NetworkSettings":{"Networks":{"host":{"IPAddress":""}}}}`, "web", nil},
	}
	for _, c := range cases {
		if got := Origins(container(t, c.raw), c.router); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: Origins = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestIconLinks(t *testing.T) {
	base, _ := url.Parse("http://192.0.2.11:8080/")
	page := []byte(`<html><head>
		<link rel="stylesheet" href="/app.css">
		<link rel="icon" type="image/png" sizes="16x16" href="/small.png">
		<LINK REL="icon" sizes="192x192 32x32" href='icons/big.png'>
		<link href="https://cdn.example.net/x.png" rel="icon" sizes="512x512">
		<link rel="shortcut icon" href="https://app.example.com/own.ico">
		<link rel="apple-touch-icon" href="/touch.png">
		<link rel="icon" href="javascript:alert(1)">
	</head></html>`)
	want := []string{
		"http://192.0.2.11:8080/touch.png",
		"http://192.0.2.11:8080/icons/big.png",
		"http://192.0.2.11:8080/small.png",
		"http://192.0.2.11:8080/own.ico",
	}
	if got := iconLinks(page, base, "app.example.com"); !reflect.DeepEqual(got, want) {
		t.Fatalf("iconLinks =\n%v\nwant\n%v", got, want)
	}
}

func TestImageType(t *testing.T) {
	cases := []struct {
		header string
		data   []byte
		want   string
		ok     bool
	}{
		{"", png, "image/png", true},
		{"application/octet-stream", []byte("\x00\x00\x01\x00\x01\x00"), "image/x-icon", true},
		{"image/vnd.microsoft.icon", []byte("not sniffable"), "image/x-icon", true},
		{"text/plain", []byte(`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"></svg>`), "image/svg+xml", true},
		{"text/html", []byte("<html>login</html>"), "", false},
		{"image/png", nil, "", false},
	}
	for _, c := range cases {
		if got, ok := imageType(c.header, c.data); got != c.want || ok != c.ok {
			t.Errorf("imageType(%q, %q) = %q, %v; want %q, %v", c.header, c.data, got, ok, c.want, c.ok)
		}
	}
}

func TestFetchFavicon(t *testing.T) {
	var hosts []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hosts = append(hosts, r.Host)
		mu.Unlock()
		switch r.URL.Path {
		case "/":
			io.WriteString(w, `<link rel="icon" href="/missing.png"><link rel="apple-touch-icon" href="/login">`)
		case "/login":
			http.Redirect(w, r, "https://login.example.net/", http.StatusFound)
		case "/favicon.ico":
			w.Write(png)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	icon, err := FetchFavicon(context.Background(), NewFaviconClient(), srv.URL, "app.example.com")
	if err != nil || icon.ContentType != "image/png" || string(icon.Data) != string(png) {
		t.Fatalf("FetchFavicon = %+v, %v", icon, err)
	}
	for _, h := range hosts {
		if h != "app.example.com" {
			t.Fatalf("request with Host %q", h)
		}
	}

	empty := httptest.NewServer(http.NotFoundHandler())
	defer empty.Close()
	if _, err := FetchFavicon(context.Background(), NewFaviconClient(), empty.URL, "app.example.com"); err == nil {
		t.Fatal("no favicon reported as found")
	}
}

type iconSink struct {
	mu    sync.Mutex
	icons map[string]string
}

func (s *iconSink) SetFavicon(_ context.Context, host, contentType string, data []byte, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.icons[host] = contentType
	return nil
}

func (s *iconSink) get(host string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.icons[host]
}

func TestWatcherFetchesFavicons(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			w.Write(png)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	c := Container{Labels: map[string]string{
		"traefik.http.routers.a.rule":                      "Host(`a.example.com`)",
		"traefik.http.routers.a.middlewares":               "traefik-authz",
		"traefik.http.services.a.loadbalancer.server.port": port,
	}}
	c.NetworkSettings.Networks = map[string]struct {
		IPAddress string `json:"IPAddress"`
	}{"main": {IPAddress: "127.0.0.1"}}
	icons := &iconSink{icons: map[string]string{}}
	changes := make(chan struct{}, 4)
	w := &Watcher{
		Engine: &fakeEngine{containers: []Container{c}}, Sink: &fakeSink{}, Icons: icons, IconClient: NewFaviconClient(),
		Middleware: "traefik-authz", OnChange: func() { changes <- struct{}{} },
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: time.Now,
	}
	if _, err := w.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(5 * time.Second)
	for icons.get("a.example.com") == "" {
		select {
		case <-changes:
		case <-deadline:
			t.Fatal("favicon not fetched")
		}
	}
	if got := icons.get("a.example.com"); got != "image/png" {
		t.Fatalf("stored %q", got)
	}
	for w.iconsActive.Load() {
		time.Sleep(10 * time.Millisecond)
	}
	if job, due := w.iconDue(c, store.App{Host: "a.example.com", Router: "a"}, time.Now()); due {
		t.Fatalf("fetched again right away: %+v", job)
	}
	if _, due := w.iconDue(c, store.App{Host: "a.example.com", Router: "a"}, time.Now().Add(25*time.Hour)); !due {
		t.Fatal("not refreshed after a day")
	}
}
