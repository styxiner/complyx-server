ARG RUST_VERSION=1.88
ARG APP_NAME=complyx-server
# ---------------------------------------------------------------------------
# Stage 1: build
# ---------------------------------------------------------------------------
FROM rust:${RUST_VERSION}-alpine3.21 AS build
ARG APP_NAME
WORKDIR /app

RUN apk add --no-cache \
  clang \
  lld \
  musl-dev \
  git \
  protobuf-dev \
  protobuf \
  pkgconf \
  openssl-dev

COPY . .

RUN --mount=type=cache,target=/app/target/ \
  --mount=type=cache,target=/usr/local/cargo/git/db \
  --mount=type=cache,target=/usr/local/cargo/registry/ \
  cargo build --locked --release --bin complyx-server && \
  cp ./target/release/complyx-server /bin/complyx-server

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
FROM alpine:3.21 AS runtime

RUN apk add --no-cache ca-certificates tzdata openssl

RUN addgroup -S complyx && adduser -S -G complyx complyx

RUN mkdir -p /var/lib/complyx/pki /etc/complyx && \
  chown -R complyx:complyx /var/lib/complyx /etc/complyx

COPY --from=build /bin/complyx-server /bin/complyx-server
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 9000 9001
USER complyx

ENV COMPLYX_GRPC_PORT=9000 \
  COMPLYX_ENROLL_PORT=9001 \
  COMPLYX_CA_DIR=/var/lib/complyx/pki \
  COMPLYX_LOG_FORMAT=json \
  COMPLYX_LOG_LEVEL=info

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/bin/complyx-server"]
