// Package discovery finds the Traefik routers that use the authz middleware,
// from Docker container labels, and records their hosts as apps.
//
// A router counts when its traefik.http.routers.<router>.middlewares label
// lists the middleware by name, bare or as <name>@docker. Its hosts come from
// the Host(...) matchers of traefik.http.routers.<router>.rule. The optional
// container labels traefik-authz.name and traefik-authz.icon set the app's
// display name and icon; without a name the router name is used.
package discovery

import (
	"regexp"
	"sort"
	"strings"

	"traefik-authz/internal/store"
)

const (
	routerPrefix = "traefik.http.routers."
	nameLabel    = "traefik-authz.name"
	iconLabel    = "traefik-authz.icon"
	enableLabel  = "traefik.enable"
)

var (
	hostMatcher = regexp.MustCompile(`(?:^|[^A-Za-z0-9_])Host\(([^)]*)\)`)
	quoted      = regexp.MustCompile("`([^`]*)`|\"([^\"]*)\"|'([^']*)'")
)

// AppsFromLabels returns one app per host of every router in labels that
// uses the middleware, sorted by host. A container labelled
// traefik.enable=false yields nothing.
func AppsFromLabels(labels map[string]string, middleware string) []store.App {
	if strings.EqualFold(strings.TrimSpace(labels[enableLabel]), "false") {
		return nil
	}
	byHost := map[string]store.App{}
	for key, value := range labels {
		router, ok := routerOf(key, ".middlewares")
		if !ok || !UsesMiddleware(value, middleware) {
			continue
		}
		name := strings.TrimSpace(labels[nameLabel])
		if name == "" {
			name = router
		}
		for _, host := range HostsFromRule(labels[routerPrefix+router+".rule"]) {
			byHost[host] = store.App{Host: host, Router: router, Name: name, Icon: strings.TrimSpace(labels[iconLabel])}
		}
	}
	apps := make([]store.App, 0, len(byHost))
	for _, a := range byHost {
		apps = append(apps, a)
	}
	sort.Slice(apps, func(i, j int) bool { return apps[i].Host < apps[j].Host })
	return apps
}

func routerOf(key, suffix string) (string, bool) {
	if !strings.HasPrefix(key, routerPrefix) || !strings.HasSuffix(key, suffix) {
		return "", false
	}
	router := strings.TrimSuffix(strings.TrimPrefix(key, routerPrefix), suffix)
	return router, router != "" && !strings.Contains(router, ".")
}

// UsesMiddleware reports whether a comma-separated middlewares label value
// lists name, bare or with the @docker provider suffix.
func UsesMiddleware(value, name string) bool {
	for _, m := range strings.Split(value, ",") {
		m = strings.TrimSpace(m)
		if m == name || m == name+"@docker" {
			return true
		}
	}
	return false
}

// HostsFromRule returns the normalized hosts of every Host(...) matcher in a
// Traefik rule, in order and without duplicates. Both Host(`a`, `b`) and
// Host(`a`) || Host(`b`) are understood; HostRegexp and HostSNI are not
// hosts and are ignored.
func HostsFromRule(rule string) []string {
	var hosts []string
	seen := map[string]bool{}
	for _, m := range hostMatcher.FindAllStringSubmatch(rule, -1) {
		for _, q := range quoted.FindAllStringSubmatch(m[1], -1) {
			host := store.NormalizeHost(q[1] + q[2] + q[3])
			if host != "" && !seen[host] {
				seen[host] = true
				hosts = append(hosts, host)
			}
		}
	}
	return hosts
}
