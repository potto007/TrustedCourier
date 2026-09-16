# TrustedCourier with the bundled OpenBao Backend Plugin, as static binaries
# built against Go's validated FIPS 140-3 module (ADR-0027). Build from the
# repository root:
#
#   docker build -f deploy/Dockerfile -t trustedcourier .
#
# deploy/compose.yaml does this for you.

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY sdk/plugin/go.mod sdk/plugin/go.sum ./sdk/plugin/
COPY plugins/openbao/go.mod plugins/openbao/go.sum ./plugins/openbao/
RUN go mod download && go -C plugins/openbao mod download
COPY . .
RUN scripts/build-release.sh /out

FROM alpine:3.22
RUN apk add --no-cache ca-certificates \
    # The user Backend Plugins run as: separate from root, which the server
    # runs as so it can switch to it (ADR-0011). It must not be able to
    # read the config or own the data directory.
    && addgroup -g 65532 trustedcourier-plugin \
    && adduser -D -H -u 65532 -G trustedcourier-plugin -s /sbin/nologin trustedcourier-plugin \
    && mkdir -p /etc/trustedcourier /var/lib/trustedcourier/data /var/lib/trustedcourier/openbao \
        /run/trustedcourier /usr/local/lib/trustedcourier/plugins /openbao/seal \
    && chmod 700 /var/lib/trustedcourier/data /openbao/seal \
    && chmod 755 /var/lib/trustedcourier/openbao
COPY --from=build /out/tc /usr/local/bin/tc
COPY --from=build /out/openbao-plugin /usr/local/lib/trustedcourier/plugins/openbao
COPY --from=build /out/SHA256SUMS /usr/local/lib/trustedcourier/SHA256SUMS
ENV TC_ADMIN_SOCKET=/run/trustedcourier/admin.sock
# Agent API over TLS.
EXPOSE 8200
# No ENTRYPOINT, so `docker compose run trustedcourier tc init ...` reads
# as it runs.
CMD ["tc", "server", "run", "--config", "/etc/trustedcourier/trustedcourier.yaml"]
