#!/bin/sh
set -e

PKI_DIR="${COMPLYX_CA_DIR:-/var/lib/complyx/pki}"
mkdir -p "$PKI_DIR"

# ---------------------------------------------------------------------------
# Si ya existen todos los certificados, arrancar directamente
# ---------------------------------------------------------------------------
if [ -f "$PKI_DIR/server.crt" ] && [ -f "$PKI_DIR/server.key" ] && [ -f "$PKI_DIR/ca.crt" ]; then
    echo "[entrypoint] certificados existentes, arrancando"
    exec "$@"
fi

# ---------------------------------------------------------------------------
# CA raíz
#
# IMPORTANTE: si ca.crt/ca.key no existen, los generamos aquí con openssl
# para tener server.crt listo ANTES del primer arranque del servidor.
# En el primer arranque, el servidor Rust detecta que ya existen ca.crt y
# ca.key y los carga en lugar de regenerarlos — así la CA es la misma.
# ---------------------------------------------------------------------------
if [ ! -f "$PKI_DIR/ca.crt" ] || [ ! -f "$PKI_DIR/ca.key" ]; then
    echo "[entrypoint] generando CA raíz (ECDSA P-256)..."

    openssl genpkey \
        -algorithm EC \
        -pkeyopt ec_paramgen_curve:P-256 \
        -out "$PKI_DIR/ca.key"

    openssl req -new -x509 \
        -key "$PKI_DIR/ca.key" \
        -subj "/CN=Complyx Internal CA/O=Complyx" \
        -days 3650 \
        -extensions v3_ca \
        -out "$PKI_DIR/ca.crt"

    chmod 600 "$PKI_DIR/ca.key"
    echo "[entrypoint] CA generada"
fi

# ---------------------------------------------------------------------------
# Certificado del servidor con SAN
#
# El SAN debe incluir todos los nombres/IPs por los que los agentes
# se conectarán. Añade aquí el hostname o IP pública si es necesario.
# COMPLYX_SERVER_HOSTNAMES acepta una lista separada por comas.
# ---------------------------------------------------------------------------
echo "[entrypoint] generando certificado del servidor (ECDSA P-256)..."

# Construir la lista de SANs
BASE_SANS="DNS:localhost,IP:127.0.0.1"

if [ -n "$COMPLYX_SERVER_HOSTNAMES" ]; then
    # Añadir hostnames/IPs adicionales desde la variable de entorno
    # Ejemplo: COMPLYX_SERVER_HOSTNAMES="complyx.ejemplo.com,192.168.1.10"
    for entry in $(echo "$COMPLYX_SERVER_HOSTNAMES" | tr ',' ' '); do
        case "$entry" in
            [0-9]*) BASE_SANS="${BASE_SANS},IP:${entry}" ;;
            *)      BASE_SANS="${BASE_SANS},DNS:${entry}" ;;
        esac
    done
fi

echo "[entrypoint] SANs del servidor: $BASE_SANS"

# Generar clave del servidor
openssl genpkey \
    -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-256 \
    -out "$PKI_DIR/server.key"

# Generar CSR con SAN inline
openssl req -new \
    -key "$PKI_DIR/server.key" \
    -subj "/CN=complyx-server/O=Complyx" \
    -addext "subjectAltName=${BASE_SANS}" \
    -out "$PKI_DIR/server.csr"

# Firmar con la CA
openssl x509 -req \
    -in "$PKI_DIR/server.csr" \
    -CA "$PKI_DIR/ca.crt" \
    -CAkey "$PKI_DIR/ca.key" \
    -CAcreateserial \
    -days 3650 \
    -copy_extensions copyall \
    -out "$PKI_DIR/server.crt"

rm -f "$PKI_DIR/server.csr"
chmod 600 "$PKI_DIR/server.key"

# Verificar el resultado
echo "[entrypoint] certificado del servidor generado:"
openssl x509 -in "$PKI_DIR/server.crt" -noout \
    -subject -issuer -dates \
    -ext subjectAltName 2>/dev/null || \
openssl x509 -in "$PKI_DIR/server.crt" -noout \
    -subject -issuer -dates

echo "[entrypoint] PKI lista en $PKI_DIR"
exec "$@"
