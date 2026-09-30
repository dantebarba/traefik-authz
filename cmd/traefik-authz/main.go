// Command traefik-authz is a forward-auth authorization service for Traefik.
//
// It runs after a forward-auth login, reads the signed-in user from a header
// and allows or denies each request by host, from per-user grants kept in
// SQLite and managed from an embedded admin PWA. The hosts are discovered
// from the Docker labels of the routers that use its middleware.
//
//	traefik-authz              serve (settings from the environment, see README)
//	traefik-authz healthcheck  exit 0 when the local server answers /healthz
//	traefik-authz version      print the version
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"traefik-authz/internal/authz"
	"traefik-authz/internal/config"
	"traefik-authz/internal/discovery"
	"traefik-authz/internal/store"
	"traefik-authz/internal/web"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Println(version)
			return
		case "healthcheck":
			os.Exit(healthcheck())
		default:
			fmt.Fprintf(os.Stderr, "usage: traefik-authz [healthcheck|version]\n")
			os.Exit(2)
		}
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel()}))
	if err := run(log); err != nil {
		log.Error("traefik-authz stopped", "err", err)
		os.Exit(1)
	}
}

func logLevel() slog.Level {
	var level slog.Level
	if err := level.UnmarshalText([]byte(os.Getenv("LOG_LEVEL"))); err != nil {
		return slog.LevelInfo
	}
	return level
}

func run(log *slog.Logger) error {
	cfg, err := config.FromEnv(os.Getenv)
	if err != nil {
		return err
	}
	db, err := store.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()
	docker, err := discovery.NewDocker(cfg.DockerHost)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	authorizer := authz.New(cfg.Admins, db)
	watcher := &discovery.Watcher{
		Engine:     docker,
		Sink:       db,
		Middleware: cfg.MiddlewareName,
		Interval:   cfg.ResyncInterval,
		Retry:      10 * time.Second,
		OnChange:   authorizer.Invalidate,
		Log:        log,
		Now:        time.Now,
	}
	go watcher.Run(ctx)

	server := &http.Server{
		Addr: cfg.ListenAddr,
		Handler: (&web.Server{
			UserHeader: cfg.UserHeader,
			Authz:      authorizer,
			Store:      db,
			Log:        log,
			Now:        time.Now,
		}).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errc := make(chan error, 1)
	go func() { errc <- server.ListenAndServe() }()
	log.Info("traefik-authz listening", "addr", cfg.ListenAddr, "version", version, "middleware", cfg.MiddlewareName, "admins", len(cfg.Admins))

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func healthcheck() int {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck: LISTEN_ADDR is not host:port")
		return 1
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort("127.0.0.1", port) + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck:", resp.Status)
		return 1
	}
	return 0
}
