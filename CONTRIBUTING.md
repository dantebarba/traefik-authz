# Contributing

## Checks

```sh
test -z "$(gofmt -l .)" && go vet ./... && go test -race ./...
sh -n scripts/scan-secrets.sh .githooks/pre-push
sh scripts/scan-secrets.sh
docker build -t traefik-authz .
```

CI runs them on every push and pull request. Without Go installed, run the Go checks in Docker:

```sh
docker run --rm -v "$PWD":/src -w /src -e GOFLAGS=-buildvcs=false golang:1.26 go test ./...
```

The tests need no Docker daemon and no network: the store runs on in-memory SQLite and the
Docker client talks to a fake engine on a temporary unix socket.

To run the service locally, set the variables from `.env.example` and `go run ./cmd/traefik-authz`,
then send the user header yourself:

```sh
curl -H 'X-Forwarded-User: admin@example.com' -H 'X-Forwarded-Host: whoami.example.com' localhost:8080/check
```

## Layout

- `cmd/traefik-authz`: the binary, wiring config, store, discovery and web.
- `internal/config`: settings from the environment.
- `internal/store`: SQLite storage (pure Go `modernc.org/sqlite`, no CGO).
- `internal/authz`: the `/check` rules and the in-memory grant cache.
- `internal/discovery`: Docker labels → apps, the Docker API client and the watcher.
- `internal/web`: HTTP handlers, the 403 page and the embedded PWA under `static/`.

## Rules

- No personal data: no real host names, addresses, e-mail addresses, user names or tokens in
  code, tests, docs or commit messages. Use `example.com`. Commit with a noreply identity.
- Private values go in `.env` (ignored) or in the sibling `traefik-authz-env` directory next to
  the main checkout, which `.envrc` loads, together with the private string list that
  `scripts/scan-secrets.sh` checks; `.githooks/pre-push` runs it before every push.
- Static Go binary (`CGO_ENABLED=0`); dependencies are the standard library and
  `modernc.org/sqlite`. The Docker API is spoken over plain `net/http`.
- The PWA is plain HTML, CSS and JS: no build step, no framework, no external requests.
- Doc comments only; no inline comments.
