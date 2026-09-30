package config

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func env(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

func TestDefaults(t *testing.T) {
	c, err := FromEnv(env(map[string]string{"ADMIN_EMAILS": "admin@example.com"}))
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		UserHeader:     "X-Forwarded-User",
		Admins:         []string{"admin@example.com"},
		MiddlewareName: "traefik-authz",
		DBPath:         "/data/authz.db",
		ListenAddr:     ":8080",
		DockerHost:     "unix:///var/run/docker.sock",
		ResyncInterval: 5 * time.Minute,
	}
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("config = %+v, want %+v", c, want)
	}
}

func TestOverrides(t *testing.T) {
	c, err := FromEnv(env(map[string]string{
		"ADMIN_EMAILS":    " A@example.com, b@example.com ;c@example.com\n",
		"USER_HEADER":     "Remote-Email",
		"MIDDLEWARE_NAME": "authz",
		"DB_PATH":         "/tmp/x.db",
		"LISTEN_ADDR":     ":9000",
		"DOCKER_HOST":     "tcp://proxy:2375",
		"RESYNC_INTERVAL": "30s",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.Admins, []string{"a@example.com", "b@example.com", "c@example.com"}) {
		t.Fatalf("admins = %q", c.Admins)
	}
	if c.UserHeader != "Remote-Email" || c.MiddlewareName != "authz" || c.DBPath != "/tmp/x.db" || c.ListenAddr != ":9000" || c.DockerHost != "tcp://proxy:2375" || c.ResyncInterval != 30*time.Second {
		t.Fatalf("config = %+v", c)
	}
}

func TestErrorsNameTheVariable(t *testing.T) {
	if _, err := FromEnv(env(map[string]string{})); err == nil || !strings.Contains(err.Error(), "ADMIN_EMAILS") {
		t.Fatalf("missing admins: %v", err)
	}
	_, err := FromEnv(env(map[string]string{"ADMIN_EMAILS": "a@example.com", "RESYNC_INTERVAL": "soon"}))
	if err == nil || !strings.Contains(err.Error(), "RESYNC_INTERVAL") || strings.Contains(err.Error(), "soon") {
		t.Fatalf("bad interval: %v", err)
	}
}
