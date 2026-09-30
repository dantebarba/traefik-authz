// Package config reads the service settings from the environment. Errors name
// the variable, never its value.
package config

import (
	"fmt"
	"strings"
	"time"
)

// Config holds every setting of the service.
type Config struct {
	UserHeader     string
	Admins         []string
	MiddlewareName string
	DBPath         string
	ListenAddr     string
	DockerHost     string
	ResyncInterval time.Duration
}

// FromEnv reads the settings through getenv, applying the defaults.
// ADMIN_EMAILS is required: without an admin nobody could open the panel.
func FromEnv(getenv func(string) string) (Config, error) {
	c := Config{
		UserHeader:     or(getenv("USER_HEADER"), "X-Forwarded-User"),
		Admins:         splitList(getenv("ADMIN_EMAILS")),
		MiddlewareName: or(getenv("MIDDLEWARE_NAME"), "traefik-authz"),
		DBPath:         or(getenv("DB_PATH"), "/data/authz.db"),
		ListenAddr:     or(getenv("LISTEN_ADDR"), ":8080"),
		DockerHost:     or(getenv("DOCKER_HOST"), "unix:///var/run/docker.sock"),
		ResyncInterval: 5 * time.Minute,
	}
	if len(c.Admins) == 0 {
		return Config{}, fmt.Errorf("ADMIN_EMAILS is empty: list at least one admin e-mail address")
	}
	if v := strings.TrimSpace(getenv("RESYNC_INTERVAL")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return Config{}, fmt.Errorf("RESYNC_INTERVAL must be a positive duration such as 5m")
		}
		c.ResyncInterval = d
	}
	return c, nil
}

func or(value, fallback string) string {
	if v := strings.TrimSpace(value); v != "" {
		return v
	}
	return fallback
}

func splitList(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		out = append(out, strings.ToLower(f))
	}
	return out
}
