package discovery

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const maxFavicon = 256 << 10

var (
	linkTag   = regexp.MustCompile(`(?is)<link\b[^>]*>`)
	attribute = regexp.MustCompile(`(?is)([a-z][a-z0-9-]*)\s*=\s*("[^"]*"|'[^']*'|[^\s"'>]+)`)
)

// Origins returns the base URLs, one per network address, at which the
// container behind router answers inside Docker: the scheme and port come from
// the router's Traefik service labels, or from the container's only exposed
// port. It returns nothing when the port cannot be told.
func Origins(c Container, router string) []string {
	service := strings.TrimSuffix(label(c.Labels, routerPrefix+router+".service"), "@docker")
	if service == "" {
		service = onlyService(c.Labels)
	}
	prefix := "traefik.http.services." + service + ".loadbalancer.server."
	port := ""
	scheme := "http"
	if service != "" {
		port = strings.TrimSpace(label(c.Labels, prefix+"port"))
		if s := strings.TrimSpace(label(c.Labels, prefix+"scheme")); s == "https" {
			scheme = s
		}
	}
	if port == "" {
		port = onlyPort(c)
	}
	if _, err := strconv.Atoi(port); err != nil {
		return nil
	}
	var origins []string
	for _, n := range c.NetworkSettings.Networks {
		if ip := net.ParseIP(n.IPAddress); ip != nil {
			origins = append(origins, scheme+"://"+net.JoinHostPort(ip.String(), port))
		}
	}
	sort.Strings(origins)
	return origins
}

func onlyService(labels map[string]string) string {
	const prefix = "traefik.http.services."
	services := map[string]bool{}
	for key := range labels {
		if len(key) <= len(prefix) || !strings.EqualFold(key[:len(prefix)], prefix) {
			continue
		}
		if name, _, ok := strings.Cut(key[len(prefix):], "."); ok && name != "" {
			services[name] = true
		}
	}
	if len(services) != 1 {
		return ""
	}
	for s := range services {
		return s
	}
	return ""
}

func onlyPort(c Container) string {
	ports := map[int]bool{}
	for _, p := range c.Ports {
		if p.Type == "" || p.Type == "tcp" {
			ports[p.PrivatePort] = true
		}
	}
	if len(ports) != 1 {
		return ""
	}
	for p := range ports {
		return strconv.Itoa(p)
	}
	return ""
}

// NewFaviconClient returns the HTTP client favicons are fetched with: short
// timeouts, redirects only within the same origin, and no certificate checks,
// since containers serving HTTPS inside Docker mostly use self-signed
// certificates and an icon is not worth refusing over that.
func NewFaviconClient() *http.Client {
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ResponseHeaderTimeout: 5 * time.Second},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 || req.URL.Host != via[0].URL.Host {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// Favicon is an icon fetched from an app.
type Favicon struct {
	ContentType string
	Data        []byte
}

// FetchFavicon asks the app at origin, as host, for its home page and follows
// the best <link rel="...icon"> it declares, falling back to /favicon.ico.
// Every request stays on origin: icons served from another host are skipped.
func FetchFavicon(ctx context.Context, client *http.Client, origin, host string) (Favicon, error) {
	base, err := url.Parse(origin + "/")
	if err != nil {
		return Favicon{}, err
	}
	candidates := []string{}
	if page, _, err := get(ctx, client, base, host); err == nil {
		candidates = iconLinks(page, base, host)
	}
	candidates = append(candidates, base.ResolveReference(&url.URL{Path: "/favicon.ico"}).String())
	var errs []error
	for _, c := range candidates {
		u, _ := url.Parse(c)
		data, contentType, err := get(ctx, client, u, host)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if ct, ok := imageType(contentType, data); ok {
			return Favicon{ContentType: ct, Data: data}, nil
		}
		errs = append(errs, fmt.Errorf("%s: not an image", u.Path))
	}
	return Favicon{}, errors.Join(errs...)
}

func get(ctx context.Context, client *http.Client, u *url.URL, host string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, "", err
	}
	req.Host = host
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("%s: %s", u.Path, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFavicon+1))
	if err != nil {
		return nil, "", err
	}
	if len(data) > maxFavicon {
		return nil, "", fmt.Errorf("%s: larger than %d bytes", u.Path, maxFavicon)
	}
	return data, resp.Header.Get("Content-Type"), nil
}

// iconLinks returns the icon URLs a page declares, best first: an
// apple-touch-icon, then icons by declared size. Links to another host are
// kept only when that host is the app's own, and are then fetched on base.
func iconLinks(page []byte, base *url.URL, host string) []string {
	type link struct {
		href  string
		score int
	}
	var links []link
	for _, tag := range linkTag.FindAll(page, -1) {
		attrs := map[string]string{}
		for _, m := range attribute.FindAllSubmatch(tag, -1) {
			attrs[strings.ToLower(string(m[1]))] = strings.Trim(string(m[2]), `"'`)
		}
		rel := strings.Fields(strings.ToLower(attrs["rel"]))
		score := 0
		for _, r := range rel {
			switch r {
			case "apple-touch-icon", "apple-touch-icon-precomposed":
				score = 10000
			case "icon":
				score = max(score, 1+largestSize(attrs["sizes"]))
			}
		}
		href := strings.TrimSpace(attrs["href"])
		if score == 0 || href == "" {
			continue
		}
		ref, err := url.Parse(href)
		if err != nil || (ref.Scheme != "" && ref.Scheme != "http" && ref.Scheme != "https") {
			continue
		}
		if ref.Host != "" {
			if !strings.EqualFold(ref.Hostname(), host) {
				continue
			}
			ref.Scheme, ref.Host = "", ""
		}
		links = append(links, link{href: base.ResolveReference(ref).String(), score: score})
	}
	sort.SliceStable(links, func(i, j int) bool { return links[i].score > links[j].score })
	out := make([]string, len(links))
	for i, l := range links {
		out[i] = l.href
	}
	return out
}

func largestSize(sizes string) int {
	best := 0
	for _, s := range strings.Fields(strings.ToLower(sizes)) {
		if s == "any" {
			return 1024
		}
		if w, _, ok := strings.Cut(s, "x"); ok {
			if n, err := strconv.Atoi(w); err == nil && n > best {
				best = n
			}
		}
	}
	return best
}

// imageType returns the content type to serve data with, when data is an
// image the panel can show.
func imageType(header string, data []byte) (string, bool) {
	if len(data) == 0 {
		return "", false
	}
	if bytes.Contains(bytes.ToLower(data[:min(len(data), 512)]), []byte("<svg")) {
		return "image/svg+xml", true
	}
	switch sniffed := http.DetectContentType(data); sniffed {
	case "image/png", "image/gif", "image/webp", "image/jpeg", "image/bmp":
		return sniffed, true
	case "image/x-icon":
		return "image/x-icon", true
	}
	if ct := strings.ToLower(strings.TrimSpace(strings.Split(header, ";")[0])); ct == "image/x-icon" || ct == "image/vnd.microsoft.icon" {
		return "image/x-icon", true
	}
	return "", false
}
