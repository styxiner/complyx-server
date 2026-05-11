#!/bin/sh
set -e

PKI_DIR="${COMPLYX_CA_DIR:-/var/lib/complyx/pki}"

# Si ya existe el cert del servidor, arrancar directamente
if [ -f "$PKI_DIR/server.crt" ] && [ -f "$PKI_DIR/server.key" ]; then
    exec "$@"
fi

echo "[entrypoint] server.crt no encontrado, generando..."

# Esperar a que exista la CA (la genera el propio servidor en el primer arranque,
# pero como aquí arrancamos antes, la generamos nosotros si tampoco existe)
if [ ! -f "$PKI_DIR/ca.crt" ] || [ ! -f "$PKI_DIR/ca.key" ]; then
    echo "[entrypoint] Generando CA raíz..."
    openssl genrsa -out "$PKI_DIR/ca.key" 4096
    openssl req -new -x509 \
        -key "$PKI_DIR/ca.key" \
        -subj "/CN=complyx-ca" \
        -days 3650 \
        -out "$PKI_DIR/ca.crt"
fi

# Generar clave y certificado del servidor firmado por la CA
openssl genrsa -out "$PKI_DIR/server.key" 4096

openssl req -new \
    -key "$PKI_DIR/server.key" \
    -subj "/CN=complyx-server" \
    -out "$PKI_DIR/server.csr"

openssl x509 -req \
    -in "$PKI_DIR/server.csr" \
    -CA "$PKI_DIR/ca.crt" \
    -CAkey "$PKI_DIR/ca.key" \
    -CAcreateserial \
    -days 3650 \
    -out "$PKI_DIR/server.crt"

rm "$PKI_DIR/server.csr"

echo "[entrypoint] Certificados generados en $PKI_DIR"

exec "$@"
