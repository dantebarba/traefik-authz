ARG GO_IMAGE=golang:1.26-alpine
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/traefik-authz ./cmd/traefik-authz \
    && mkdir -p /out/data

FROM ${RUNTIME_IMAGE}
COPY --from=build /out/traefik-authz /usr/local/bin/traefik-authz
COPY --from=build /out/data /data
ENV DB_PATH=/data/authz.db \
    LISTEN_ADDR=:8080
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s CMD ["/usr/local/bin/traefik-authz", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/traefik-authz"]
