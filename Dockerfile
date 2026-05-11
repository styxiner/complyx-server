ARG RUST_VERSION=1.88
ARG APP_NAME=complyx-server

# ---------------------------------------------------------------------------
# Stage 1: build
# ---------------------------------------------------------------------------
FROM rust:${RUST_VERSION}-alpine3.21 AS build
ARG APP_NAME

WORKDIR /app

# Dependencias de compilación
RUN apk add --no-cache \
  clang \
  lld \
  musl-dev \
  git \
  protobuf-dev \
  protobuf \
  pkgconf \
  openssl-dev

# Copiar el workspace completo
# Los --mount de cache aceleran rebuilds pero necesitamos el workspace entero
COPY . .

# sqlx comprueba queries en compilación contra .sqlx/ (generado con cargo sqlx prepare)
# El directorio .sqlx/ debe estar commiteado en el repo
RUN --mount=type=cache,target=/app/target/ \
  --mount=type=cache,target=/usr/local/cargo/git/db \
  --mount=type=cache,target=/usr/local/cargo/registry/ \
  cargo build --locked --release --bin complyx-server && \
  cp ./target/release/complyx-server /bin/complyx-server

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
FROM alpine:3.21 AS runtime

# ca-certificates: rustls necesita las CAs del sistema para conexiones TLS salientes
# tzdata: timestamps correctos en los logs
RUN apk add --no-cache ca-certificates tzdata

# Usuario sin privilegios
RUN addgroup -S complyx && adduser -S -G complyx complyx

# Directorios necesarios
RUN mkdir -p /var/lib/complyx/pki /etc/complyx && \
  chown -R complyx:complyx /var/lib/complyx /etc/complyx

COPY --from=build /bin/complyx-server /bin/complyx-server

# Puertos gRPC
EXPOSE 9000 9001

USER complyx

# Variables con valores por defecto (sobreescribibles desde docker-compose)
ENV COMPLYX_GRPC_PORT=9000 \
  COMPLYX_ENROLL_PORT=9001 \
  COMPLYX_CA_DIR=/var/lib/complyx/pki \
  COMPLYX_LOG_FORMAT=json \
  COMPLYX_LOG_LEVEL=info

# DATABASE_URL no tiene default aquí — se pone en docker-compose
# COMPLYX_DATABASE_URL=postgres://complyx:complyx@postgres/complyx

CMD ["/bin/complyx-server"]
