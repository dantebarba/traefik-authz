# traefik-authz

Per-user, per-service authorization for Traefik, chained after a forward-auth login.

A forward-auth login such as [traefik-forward-auth](https://github.com/thomseddon/traefik-forward-auth)
answers *who you are*. traefik-authz answers *what you may open*: it runs as a second
`forwardauth` middleware, reads the signed-in user from a header, and allows the request only
when that user holds a grant on the host. Users and grants are managed from an embedded admin
PWA; the hosts are discovered on their own from the Docker labels of the routers that use the
middleware.

```
router.middlewares = tls-headers, traefik-forward-auth, traefik-authz
                                  └── who are you?      └── may you open this host?
```

Because traefik-authz only reads a header, the login in front can be swapped (tinyauth,
oauth2-proxy, …) without touching it.

## How a request is decided

Traefik calls `GET /check` with the original request's headers. The rules, in order:

1. No user header → **403**. Covers a router that uses traefik-authz without a login in front.
2. The user is in `ADMIN_EMAILS` → **200**, everywhere, whatever the database says.
3. `X-Forwarded-Host` is not a discovered app → **403** (deny by default).
4. The user exists, is enabled and holds a grant on the app → **200**.
5. Otherwise → **403** with a page saying "You don't have access to *app*", and the attempt
   is recorded as an access request that an admin can approve with one click. Disabled users
   are denied without recording a request.

Grants are cached in memory and reloaded after every change made from the panel or found by
discovery.

## Deploy

The image is published to `ghcr.io/dantebarba/traefik-authz` for `linux/amd64` and
`linux/arm64`: `latest` follows `main`, and a `vX.Y.Z` tag publishes `X.Y.Z` and `X.Y`.

A compose file next to an existing Traefik (entrypoint `websecure`, certificate resolver
`myresolver`, external network `main`):

```yaml
services:
  traefik-forward-auth:
    image: thomseddon/traefik-forward-auth:2
    restart: unless-stopped
    networks: [main]
    environment:
      - DEFAULT_PROVIDER=google
      - PROVIDERS_GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID}
      - PROVIDERS_GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET}
      - SECRET=${FORWARD_AUTH_SECRET}
      - AUTH_HOST=auth.example.com
      - COOKIE_DOMAIN=example.com
    labels:
      - traefik.enable=true
      - traefik.http.routers.traefik-forward-auth.rule=Host(`auth.example.com`)
      - traefik.http.routers.traefik-forward-auth.entrypoints=websecure
      - traefik.http.routers.traefik-forward-auth.tls.certresolver=myresolver
      - traefik.http.routers.traefik-forward-auth.middlewares=traefik-forward-auth
      - traefik.http.middlewares.traefik-forward-auth.forwardauth.address=http://traefik-forward-auth:4181
      - traefik.http.middlewares.traefik-forward-auth.forwardauth.trustForwardHeader=true
      - traefik.http.middlewares.traefik-forward-auth.forwardauth.authResponseHeaders=X-Forwarded-User
      - traefik.http.services.traefik-forward-auth.loadbalancer.server.port=4181

  traefik-authz:
    image: ghcr.io/dantebarba/traefik-authz:latest
    restart: unless-stopped
    networks: [main]
    environment:
      - ADMIN_EMAILS=admin@example.com
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./traefik-authz:/data
    labels:
      - traefik.enable=true
      - traefik.http.middlewares.traefik-authz.forwardauth.address=http://traefik-authz:8080/check
      - traefik.http.middlewares.traefik-authz.forwardauth.trustForwardHeader=true
      - traefik.http.routers.traefik-authz.rule=Host(`authz.example.com`)
      - traefik.http.routers.traefik-authz.entrypoints=websecure
      - traefik.http.routers.traefik-authz.tls.certresolver=myresolver
      - traefik.http.routers.traefik-authz.middlewares=traefik-forward-auth
      - traefik.http.services.traefik-authz.loadbalancer.server.port=8080

  whoami:
    image: traefik/whoami
    networks: [main]
    labels:
      - traefik.enable=true
      - traefik.http.routers.whoami.rule=Host(`whoami.example.com`)
      - traefik.http.routers.whoami.entrypoints=websecure
      - traefik.http.routers.whoami.tls.certresolver=myresolver
      - traefik.http.routers.whoami.middlewares=traefik-forward-auth,traefik-authz
      - traefik-authz.name=Who am I
      - traefik-authz.icon=🪪

networks:
  main:
    external: true
```

Three things in there matter:

- **`authResponseHeaders=X-Forwarded-User` on the login middleware.** It makes Traefik
  overwrite the header with the signed-in user before traefik-authz sees it. Without it, a
  client could send its own `X-Forwarded-User` and be believed.
- **The panel router uses the login only**, not `traefik-authz`: the panel checks
  `ADMIN_EMAILS` itself and answers everyone else with a 403.
- **Every router behind the login must also list `traefik-authz`.** Once the login stops
  restricting accounts (for instance traefik-forward-auth without `WHITELIST`), a router that
  has the login but not traefik-authz is open to any account of the provider.

Then open `https://authz.example.com` as an admin. From a phone, "Add to Home Screen" installs
it as an app.

## Configuration

| Variable          | Default                       | Meaning                                                                   |
| ----------------- | ----------------------------- | ------------------------------------------------------------------------- |
| `ADMIN_EMAILS`    | *(required)*                  | Admin addresses, separated by commas or spaces: access everywhere + panel |
| `USER_HEADER`     | `X-Forwarded-User`            | Header that carries the signed-in e-mail address                          |
| `MIDDLEWARE_NAME` | `traefik-authz`               | Middleware name that discovery looks for in router labels                 |
| `DB_PATH`         | `/data/authz.db`              | SQLite database                                                           |
| `LISTEN_ADDR`     | `:8080`                       | Listen address                                                            |
| `DOCKER_HOST`     | `unix:///var/run/docker.sock` | Docker API: `unix:///path` or `tcp://host:port` (e.g. a socket proxy)     |
| `RESYNC_INTERVAL` | `5m`                          | Full rescan of the containers, on top of the start events                 |
| `LOG_LEVEL`       | `info`                        | `debug` also logs every allowed request                                   |

E-mail addresses and hosts are compared case-insensitively; ports in `X-Forwarded-Host` are
ignored.

## Discovery

traefik-authz lists the running containers at start, again on every container `start` event
and every `RESYNC_INTERVAL`. A router becomes an app when its
`traefik.http.routers.<router>.middlewares` label lists `MIDDLEWARE_NAME`, bare or as
`<name>@docker`. Its hosts come from the `Host(...)` matchers of
`traefik.http.routers.<router>.rule`; both ``Host(`a`, `b`)`` and ``Host(`a`) || Host(`b`)`` work,
and each host is its own app. `HostRegexp` rules are not discovered. Containers labelled
`traefik.enable=false` are skipped.

Optional container labels:

| Label                | Meaning                                                             |
| -------------------- | ------------------------------------------------------------------- |
| `traefik-authz.name` | Display name; defaults to the router name                           |
| `traefik-authz.icon` | An emoji or short text, or an `https://` or `/` URL of an image    |

Apps are never deleted: when a container goes away its app stays listed with the last time it
was seen, and its grants stay in place for when it comes back.

## Admin panel and API

The panel shows pending access requests (approve or dismiss), the users (add by e-mail, grant
apps with toggles, disable, delete) and the discovered apps. It is a plain HTML/JS PWA embedded
in the binary, with a service worker that keeps the shell available offline.

It talks to a JSON API under `/api/`, open to `ADMIN_EMAILS` only. State-changing calls must
send `X-Requested-With: traefik-authz`, which a cross-site form cannot.

| Call                                  | Body                             |
| ------------------------------------- | -------------------------------- |
| `GET /api/state`                      |                                  |
| `POST /api/users`                     | `{"email": "…", "name": "…"}`    |
| `PATCH /api/users/{email}`            | `{"disabled": true}`             |
| `DELETE /api/users/{email}`           |                                  |
| `PUT /api/users/{email}/apps/{id}`    |                                  |
| `DELETE /api/users/{email}/apps/{id}` |                                  |
| `POST /api/requests/approve`          | `{"email": "…", "host": "…"}`    |
| `POST /api/requests/dismiss`          | `{"email": "…", "host": "…"}`    |

Approving a request creates the user if needed and grants the app. `GET /healthz` answers
`ok` to anyone; the image's `HEALTHCHECK` runs `traefik-authz healthcheck` against it.

## Security notes

- **The user header is trusted.** Any container on the same Docker network can call
  `http://traefik-authz:8080/check` or `/api/` directly with a forged `X-Forwarded-User`,
  bypassing Traefik. On a home network this is accepted; elsewhere, put traefik-authz on a
  network only Traefik shares, or firewall the port.
- **The Docker socket is root on the host**, even mounted `:ro` (that flag only stops the
  socket file from being replaced). traefik-authz only reads `/containers/json` and `/events`;
  to enforce that, point `DOCKER_HOST` at a read-only socket proxy that allows `CONTAINERS`
  and `EVENTS`.
- Admins come from the environment, not the database, so a broken or lost database never locks
  them out.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT
