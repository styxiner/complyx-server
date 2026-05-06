# Complyx Server

Servidor de orquestación de Complyx. Gestiona los agentes distribuidos,
distribuye políticas de seguridad, recibe y persiste los resultados de
los checks, opera la PKI interna para la autenticación mTLS
y mantiene el modelo de riesgos.

## Índice

- [Requisitos](#requisitos)
- [Compilación para desarrollo](#compilación-para-desarrollo)
- [Compilación para producción](#compilación-para-producción)
- [Configuración](#configuración)
- [Operación](#operación)
- [Tests](#tests)
- [Arquitectura de crates](#arquitectura-de-crates)

---

## Requisitos

**Para compilar:**

- Rust 1.78+ con cargo ([instalación oficial](https://rust-lang.org/tools/install/))
- `protoc` — compilador de Protocol Buffers
- `sqlx-cli` — herramienta de migraciones de base de datos
- PostgreSQL 16+ corriendo localmente (para el check en compilación de sqlx)

```bash
# protoc
sudo apt install protobuf-compiler      # Debian/Ubuntu
sudo dnf install protobuf-compiler      # RHEL/Fedora
brew install protobuf                   # macOS

# sqlx-cli con soporte postgres
cargo install sqlx-cli --no-default-features --features postgres
```

**Para correr en desarrollo:**

- PostgreSQL 16+ (con usuario y base de datos creados)
- Docker (opcional, para levantar PostgreSQL sin instalarlo)

---

## Compilación para desarrollo

### 1. Clonar el repositorio

```bash
git clone https://github.com/styxiner/complyx-server.git
cd complyx-server
```

### 2. Levantar PostgreSQL

Con Docker (recomendado para desarrollo):

```bash
docker run -d \
  --name complyx-pg \
  -e POSTGRES_USER=complyx \
  -e POSTGRES_PASSWORD=complyx \
  -e POSTGRES_DB=complyx \
  -p 5432:5432 \
  postgres:16-alpine
```

O si ya tienes PostgreSQL instalado:

```bash
sudo -u postgres psql << 'SQL'
CREATE DATABASE complyx;
CREATE USER complyx WITH PASSWORD 'complyx';
ALTER DATABASE complyx OWNER TO complyx;
GRANT ALL PRIVILEGES ON DATABASE complyx TO complyx;
SQL
```

### 3. Exportar la URL de la base de datos

```bash
export DATABASE_URL="postgres://complyx:complyx@localhost/complyx"
```

Puedes añadirla a un fichero `.env` en la raíz del proyecto (sqlx lo carga automáticamente):

```bash
echo 'DATABASE_URL="postgres://complyx:complyx@localhost/complyx"' > .env
```

### 4. Aplicar las migrations

```bash
sqlx migrate run --source migrations/
```

Esto crea todas las tablas definidas en `migrations/`.
Para verificar que se aplicaron correctamente:

```bash
sqlx migrate info --source migrations/
```

### 5. Preparar los metadatos de sqlx

sqlx verifica las queries SQL contra el schema real de la BD en
tiempo de compilación. Este paso genera el directorio `.sqlx/`
con los metadatos que necesita el compilador:

```bash
cargo sqlx prepare --workspace
```

Este directorio debe commitearse al repositorio para que
la compilación funcione en entornos sin BD (CI, builds de release).

### 6. Compilar

```bash
cargo build
```

El binario queda en `target/debug/complyx-server`.

Para ejecutarlo en bare-metal habría que primero generar un par de claves a partir de la CA generada:

```bash
# Generar clave privada del servidor
sudo openssl genpkey \
  -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-256 \
  -out /var/lib/complyx/pki/server.key

# Generar CSR con SAN
sudo openssl req \
  -new \
  -key /var/lib/complyx/pki/server.key \
  -subj "/CN=complyx-server/O=Complyx" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -out /tmp/server.csr

# Firmar con la CA de Complyx
sudo openssl x509 \
  -req \
  -in /tmp/server.csr \
  -CA /var/lib/complyx/pki/ca.crt \
  -CAkey /var/lib/complyx/pki/ca.key \
  -CAcreateserial \
  -days 365 \
  -copy_extensions copyall \
  -out /var/lib/complyx/pki/server.crt

# Verificar el resultado
sudo openssl x509 \
  -in /var/lib/complyx/pki/server.crt \
  -text \
  -noout | grep -A2 "Subject Alternative"
```

---

## Compilación para producción

El servidor corre en un contenedor Docker con Alpine Linux,
por lo que el binario debe enlazarse estáticamente con musl:

```bash
# Añadir el target musl
rustup target add x86_64-unknown-linux-musl
sudo apt install musl-tools   # Debian/Ubuntu

# Compilar con perfil optimizado
cargo build --profile dist --target x86_64-unknown-linux-musl --bin complyx-server
```

El binario queda en `target/x86_64-unknown-linux-musl/dist/complyx-server`.

### Imagen Docker

```bash
docker build -t complyx-server:0.1.0 .
```

El `Dockerfile` copia el binario ya compilado, no compila dentro del contenedor:

```dockerfile
FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
COPY target/x86_64-unknown-linux-musl/dist/complyx-server /usr/bin/complyx-server
EXPOSE 9000 9001
ENTRYPOINT ["/usr/bin/complyx-server"]
```

---

## Configuración

La configuración se carga en capas con este orden de
precedencia (cada capa sobreescribe la anterior):

1. Valores por defecto compilados.
2. Fichero TOML: `/etc/complyx/server.toml` (o `COMPLYX_CONFIG_PATH`).
3. Variables de entorno con prefijo `COMPLYX_`.

```toml
# /etc/complyx/server.toml

# --- Base de datos (OBLIGATORIO) ---
database_url = "postgres://complyx:complyx@localhost/complyx"

# --- Puertos gRPC ---
# Puerto principal: requiere mTLS. Los agentes enrolados se conectan aquí.
grpc_port = 9000

# Puerto de enrolamiento: TLS one-way. Solo para el primer arranque del agente.
enroll_port = 9001

# --- PKI interna ---
# Directorio donde se almacenan la clave privada y el certificado raíz de la CA.
# La clave privada (ca.key) NUNCA debe salir de este directorio.
ca_dir = "/var/lib/complyx/pki"

# Duración en días de los certificados emitidos a los agentes.
cert_validity_days = 365

# Duración en horas de los tokens de enrolamiento de un solo uso.
enroll_token_expiry_hours = 24

# --- Orchestrator ---
# Segundos sin heartbeat tras los que un agente se marca como offline.
agent_offline_timeout_secs = 300

# --- Logging ---
log_level  = "info"     # error | warn | info | debug | trace
log_format = "json"     # json (producción) | pretty (desarrollo)
```

### Variables de entorno

|Variable|Equivalente en TOML|
|---|---|
|`COMPLYX_DATABASE_URL`|`database_url`|
|`COMPLYX_GRPC_PORT`|`grpc_port`|
|`COMPLYX_ENROLL_PORT`|`enroll_port`|
|`COMPLYX_CA_DIR`|`ca_dir`|
|`COMPLYX_LOG_LEVEL`|`log_level`|
|`COMPLYX_CONFIG_PATH`|Ruta al fichero de configuración|

---

## Operación

### Gestión del servicio

```bash
# Estado
systemctl status complyx-server

# Logs en tiempo real
journalctl -u complyx-server -f

# Reiniciar tras cambiar la configuración
systemctl restart complyx-server
```

Con Docker:

```bash
docker logs -f complyx-server
docker restart complyx-server
```

### Generar un token de enrolamiento para un agente

El administrador genera un token de un solo uso y lo pasa al
operador que va a instalar el agente en el endpoint:

```bash
# Con el binario directamente
complyx-server enroll-token --hostname web-01.ejemplo.com

# Con Docker
docker exec complyx-server complyx-server enroll-token --hostname web-01.ejemplo.com
```

Salida:

```text
Token de enrolamiento generado:
  Hostname: web-01.ejemplo.com
  Expira:   2025-05-05 10:00:00 UTC
  Token:    a3f8c2d1e9b04f7a...

Úsalo en el agente con:
  COMPLYX_ENROLL_TOKEN=a3f8c2d1... systemctl start complyx-agent
```

El token es de un solo uso: una vez que el agente lo consume
en el enrolamiento queda invalidado.

### Revocar el certificado de un agente

Si un endpoint se compromete o se da de baja,
revoca su certificado para que no pueda conectarse:

```bash
complyx-server revoke-agent --agent-id 550e8400-e29b-41d4-a716-446655440000
```

El agente recibirá un error `Unauthenticated` en su próximo poll
y dejará de comunicarse con el servidor.

### Directorios relevantes

|Ruta|Contenido|
|---|---|
|`/etc/complyx/server.toml`|Configuración del servidor|
|`/var/lib/complyx/pki/ca.crt`|Certificado raíz de la CA interna|
|`/var/lib/complyx/pki/ca.key`|Clave privada de la CA (permisos 0600, nunca exponer)|

### Migrations en producción

Las migrations se aplican automáticamente al arrancar el
servidor si hay pendientes. Para aplicarlas manualmente antes del arranque
(recomendado en producción para tener control):

```bash
# Con sqlx-cli apuntando a la BD de producción
DATABASE_URL="postgres://complyx:password@prod-host/complyx" \
sqlx migrate run --source migrations/

# Ver estado de las migrations
DATABASE_URL="postgres://complyx:password@prod-host/complyx" \
sqlx migrate info --source migrations/
```

---

## Tests

### Preparar la base de datos de test

sqlx necesita una BD real para los tests de integración.
La forma más limpia es usar una BD separada:

```bash
# Crear la BD de test
createdb complyx_test
export DATABASE_URL="postgres://complyx:complyx@localhost/complyx_test"
sqlx migrate run --source migrations/
```

O con Docker:

```bash
docker run -d \
  --name complyx-pg-test \
  -e POSTGRES_USER=complyx \
  -e POSTGRES_PASSWORD=complyx \
  -e POSTGRES_DB=complyx_test \
  -p 5433:5432 \
  postgres:16-alpine

export DATABASE_URL="postgres://complyx:complyx@localhost:5433/complyx_test"
sqlx migrate run --source migrations/
```

### Ejecutar los tests

```bash
# Todos los tests del workspace
DATABASE_URL="postgres://complyx:complyx@localhost/complyx_test" cargo test

# Tests de un crate específico
DATABASE_URL="postgres://complyx:complyx@localhost/complyx_test" cargo test -p db
DATABASE_URL="postgres://complyx:complyx@localhost/complyx_test" cargo test -p pki
DATABASE_URL="postgres://complyx:complyx@localhost/complyx_test" cargo test -p result-ingester

# Con output en pantalla (útil para debug)
DATABASE_URL="postgres://complyx:complyx@localhost/complyx_test" cargo test -- --nocapture

# Solo tests unitarios (sin BD, más rápido)
cargo test -p policy-distributor
cargo test -p orchestrator
```

### Resetear la BD de test entre ejecuciones

sqlx tiene soporte nativo para tests con BD aislada por test
usando `#[sqlx::test]`. Los tests que usan esta macro crean
su propia BD temporal y la eliminan al acabar,
así que no necesitas resetear manualmente.

Para los tests de integración que no usan `#[sqlx::test]`,
puedes resetear la BD completa:

```bash
sqlx database drop \
  --database-url postgres://complyx:complyx@localhost/complyx_test \
  -y
sqlx database create \
  --database-url postgres://complyx:complyx@localhost/complyx_test
sqlx migrate run \
  --source migrations/ \
  --database-url postgres://complyx:complyx@localhost/complyx_test
```

---

## Arquitectura de crates

Ya cuando acabe, meto la arquitectura de crates.
