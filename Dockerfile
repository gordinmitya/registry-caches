FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY *.go ./
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/simple-cache . \
 && mkdir /out/cache /out/certs

FROM gcr.io/distroless/static-debian12:nonroot
# Created here, owned by nonroot (65532), so fresh named volumes inherit that
# ownership. Binding :443 as nonroot works because Docker sets
# net.ipv4.ip_unprivileged_port_start=0 in the container.
COPY --from=build --chown=65532:65532 /out/cache /cache
COPY --from=build --chown=65532:65532 /out/certs /certs
COPY --from=build /out/simple-cache /simple-cache
# No post-quantum key share: its oversized ClientHello some corporate middleboxes mishandle.
ENV GODEBUG=tlsmlkem=0
EXPOSE 443
ENTRYPOINT ["/simple-cache"]
