package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const listTimeout = 30 * time.Second

// Container is the part of a running Docker container that discovery reads.
type Container struct {
	ID     string            `json:"Id"`
	Labels map[string]string `json:"Labels"`
}

// Docker talks to the Docker Engine API with the standard library only.
type Docker struct {
	client *http.Client
	base   string
}

// NewDocker returns a client for dockerHost, given as unix:///path/to/socket
// or tcp://host:port (a socket proxy, for instance). Unversioned API paths
// are used, so any engine answers with its own current API version.
func NewDocker(dockerHost string) (*Docker, error) {
	u, err := url.Parse(dockerHost)
	if err != nil {
		return nil, fmt.Errorf("DOCKER_HOST: %w", err)
	}
	switch u.Scheme {
	case "unix":
		socket := u.Path
		dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}
		return &Docker{client: &http.Client{Transport: &http.Transport{DialContext: dial}}, base: "http://docker"}, nil
	case "tcp", "http":
		return &Docker{client: &http.Client{}, base: "http://" + u.Host}, nil
	default:
		return nil, fmt.Errorf("DOCKER_HOST: unsupported scheme %q, want unix:// or tcp://", u.Scheme)
	}
}

// Containers lists the running containers, giving up after listTimeout so a
// stalled engine or socket proxy cannot hold up discovery.
func (d *Docker) Containers(ctx context.Context) ([]Container, error) {
	ctx, cancel := context.WithTimeout(ctx, listTimeout)
	defer cancel()
	resp, err := d.get(ctx, "/containers/json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var containers []Container
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return nil, fmt.Errorf("decode containers: %w", err)
	}
	return containers, nil
}

// Events streams container start events and calls started for each one,
// until ctx ends or the stream breaks.
func (d *Docker) Events(ctx context.Context, started func()) error {
	filters := url.QueryEscape(`{"type":["container"],"event":["start"]}`)
	resp, err := d.get(ctx, "/events?filters="+filters)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	for {
		var event struct {
			Type   string `json:"Type"`
			Action string `json:"Action"`
		}
		if err := dec.Decode(&event); err != nil {
			if err == io.EOF {
				return fmt.Errorf("docker events: stream closed")
			}
			return fmt.Errorf("docker events: %w", err)
		}
		if event.Type == "container" && event.Action == "start" {
			started()
		}
	}
}

func (d *Docker) get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.base+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker %s: %w", strings.SplitN(path, "?", 2)[0], err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		return nil, fmt.Errorf("docker %s: %s: %s", strings.SplitN(path, "?", 2)[0], resp.Status, strings.TrimSpace(string(body)))
	}
	return resp, nil
}
