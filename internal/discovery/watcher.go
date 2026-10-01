package discovery

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"traefik-authz/internal/store"
)

// Engine is what the Watcher needs from Docker.
type Engine interface {
	Containers(ctx context.Context) ([]Container, error)
	Events(ctx context.Context, started func()) error
}

// Sink records discovered apps.
type Sink interface {
	UpsertApp(ctx context.Context, app store.App, seen time.Time) error
}

// IconSink stores the favicons fetched for discovered apps.
type IconSink interface {
	SetFavicon(ctx context.Context, host, contentType string, data []byte, at time.Time) error
}

const (
	faviconRefresh = 24 * time.Hour
	faviconRetry   = time.Hour
)

// Watcher keeps the apps in a Sink in line with the running containers: it
// syncs at start, on every container start event and every Interval. With
// Icons and IconClient set, it also fetches each app's favicon from its
// container in the background: once a day per host, or an hour after a
// failed attempt.
type Watcher struct {
	Engine     Engine
	Sink       Sink
	Icons      IconSink
	IconClient *http.Client
	Middleware string
	Interval   time.Duration
	Retry      time.Duration
	OnChange   func()
	Log        *slog.Logger
	Now        func() time.Time

	iconMu      sync.Mutex
	iconNext    map[string]time.Time
	iconsActive atomic.Bool
}

type iconJob struct {
	host    string
	origins []string
}

// Sync lists the running containers once and upserts every app found,
// marking it seen now. It returns the number of apps upserted.
func (w *Watcher) Sync(ctx context.Context) (int, error) {
	containers, err := w.Engine.Containers(ctx)
	if err != nil {
		return 0, err
	}
	now := w.Now()
	var errs []error
	var jobs []iconJob
	n := 0
	for _, c := range containers {
		for _, app := range AppsFromLabels(c.Labels, w.Middleware) {
			if err := w.Sink.UpsertApp(ctx, app, now); err != nil {
				errs = append(errs, err)
				continue
			}
			n++
			if job, ok := w.iconDue(c, app, now); ok {
				jobs = append(jobs, job)
			}
		}
	}
	if n > 0 && w.OnChange != nil {
		w.OnChange()
	}
	if len(jobs) > 0 && w.iconsActive.CompareAndSwap(false, true) {
		go w.fetchIcons(ctx, jobs)
	}
	return n, errors.Join(errs...)
}

func (w *Watcher) iconDue(c Container, app store.App, now time.Time) (iconJob, bool) {
	if w.Icons == nil || w.IconClient == nil {
		return iconJob{}, false
	}
	w.iconMu.Lock()
	next, ok := w.iconNext[app.Host]
	w.iconMu.Unlock()
	if ok && now.Before(next) {
		return iconJob{}, false
	}
	origins := Origins(c, app.Router)
	return iconJob{host: app.Host, origins: origins}, len(origins) > 0
}

func (w *Watcher) fetchIcons(ctx context.Context, jobs []iconJob) {
	defer w.iconsActive.Store(false)
	fetched := 0
	for _, j := range jobs {
		ok := w.fetchIcon(ctx, j)
		wait := faviconRetry
		if ok {
			fetched++
			wait = faviconRefresh
		}
		w.iconMu.Lock()
		if w.iconNext == nil {
			w.iconNext = map[string]time.Time{}
		}
		w.iconNext[j.host] = w.Now().Add(wait)
		w.iconMu.Unlock()
	}
	if fetched > 0 && w.OnChange != nil {
		w.OnChange()
	}
}

func (w *Watcher) fetchIcon(ctx context.Context, j iconJob) bool {
	for _, origin := range j.origins {
		icon, err := FetchFavicon(ctx, w.IconClient, origin, j.host)
		if err != nil {
			w.Log.Debug("no favicon", "host", j.host, "origin", origin, "err", err)
			continue
		}
		if err := w.Icons.SetFavicon(ctx, j.host, icon.ContentType, icon.Data, w.Now()); err != nil {
			w.Log.Warn("store favicon failed", "host", j.host, "err", err)
			return false
		}
		return true
	}
	return false
}

// Run syncs until ctx ends.
func (w *Watcher) Run(ctx context.Context) {
	wake := make(chan struct{}, 1)
	notify := func() {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
	go w.watchEvents(ctx, notify)
	ticker := time.NewTicker(w.Interval)
	defer ticker.Stop()
	for {
		if n, err := w.Sync(ctx); err != nil && ctx.Err() == nil {
			w.Log.Warn("discovery sync failed", "err", err)
		} else if err == nil {
			w.Log.Debug("discovery synced", "apps", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-wake:
		}
	}
}

func (w *Watcher) watchEvents(ctx context.Context, notify func()) {
	for {
		err := w.Engine.Events(ctx, notify)
		if ctx.Err() != nil {
			return
		}
		w.Log.Warn("docker events lost, reconnecting", "err", err, "in", w.Retry)
		select {
		case <-ctx.Done():
			return
		case <-time.After(w.Retry):
		}
		notify()
	}
}
