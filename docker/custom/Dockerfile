FROM golang:1.26-trixie AS builder
WORKDIR /src
ENV GOFLAGS=-mod=readonly
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
ARG COMMIT_SHA=custom-url-downloads
RUN CGO_ENABLED=1 go build -trimpath -ldflags "-s -w -X github.com/drakkan/sftpgo/v2/internal/version.commit=${COMMIT_SHA}" -o /out/sftpgo .

FROM debian:trixie-slim
RUN apt-get update && apt-get install --no-install-recommends -y ca-certificates media-types curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 sftpgo \
    && useradd --uid 1000 --gid 1000 --no-create-home --home-dir /var/lib/sftpgo --shell /usr/sbin/nologin sftpgo \
    && mkdir -p /etc/sftpgo /usr/share/sftpgo /var/lib/sftpgo /srv/sftpgo/data /srv/sftpgo/backups \
    && chown -R 1000:1000 /var/lib/sftpgo /srv/sftpgo
COPY --from=builder /out/sftpgo /usr/local/bin/sftpgo
COPY sftpgo.json /etc/sftpgo/sftpgo.json
COPY templates /usr/share/sftpgo/templates
COPY static /usr/share/sftpgo/static
COPY openapi /usr/share/sftpgo/openapi
ENV SFTPGO_LOG_FILE_PATH=""
WORKDIR /var/lib/sftpgo
USER 1000:1000
EXPOSE 8080 2022
CMD ["sftpgo", "serve", "--config-dir", "/etc/sftpgo"]
