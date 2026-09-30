package discovery

import (
	"context"
	"errors"
	"log/slog"
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

// Watcher keeps the apps in a Sink in line with the running containers: it
// syncs at start, on every container start event and every Interval.
type Watcher struct {
	Engine     Engine
	Sink       Sink
	Middleware string
	Interval   time.Duration
	Retry      time.Duration
	OnChange   func()
	Log        *slog.Logger
	Now        func() time.Time
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
	n := 0
	for _, c := range containers {
		for _, app := range AppsFromLabels(c.Labels, w.Middleware) {
			if err := w.Sink.UpsertApp(ctx, app, now); err != nil {
				errs = append(errs, err)
				continue
			}
			n++
		}
	}
	if n > 0 && w.OnChange != nil {
		w.OnChange()
	}
	return n, errors.Join(errs...)
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
