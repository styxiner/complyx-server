//! Acceso de la PKI a la capa de base de datos.
//!
//! Este módulo actúa como fachada sobre `db::certs` para que los otros módulos
//! del crate `pki` solo necesiten importar desde aquí, sin acoplarse directamente
//! a `db`. Facilita los tests: se puede mockear `store` sin tocar `db`.

use chrono::DateTime;
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use db::certs as db_certs;
pub use db::certs::{AgentCertRow, EnrollTokenRow};

use crate::PkiError;

// Persiste el certificado emitido a un agente.
pub async fn save_agent_cert(
    pool: &PgPool,
    agent_id: Uuid,
    cert_pem: &str,
    serial: &str,
) -> Result<(), PkiError> {
    db_certs::store_cert(pool, agent_id, cert_pem, serial)
        .await
        .map_err(PkiError::Database)
}

// Obtiene el certificado de un agente.
pub async fn get_agent_cert(
    pool: &PgPool,
    agent_id: Uuid,
) -> Result<Option<AgentCertRow>, PkiError> {
    db_certs::get_cert(pool, agent_id)
        .await
        .map_err(PkiError::Database)
}

// Comprueba si el número de serie está revocado. Usada por el interceptor gRPC en cada request
pub async fn is_serial_revoked(pool: &PgPool, serial: &str) -> Result<bool, PkiError> {
    db_certs::is_revoked(pool, serial)
        .await
        .map_err(PkiError::Database)
}

// Persiste un nuevo token de enrolamiento (hash SHA-256 del token en claro).
pub async fn save_token(
    pool: &PgPool,
    token_hash: &str,
    hostname_hint: Option<&str>,
    expires_at: DateTime<Utc>,
) -> Result<Uuid, PkiError> {
    db_certs::save_enroll_token(pool, token_hash, hostname_hint, expires_at.naive_utc())
        .await
        .map_err(PkiError::Database)
}

// Busca un token por su hash.
pub async fn find_token(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Option<EnrollTokenRow>, PkiError> {
    db_certs::find_enroll_token(pool, token_hash)
        .await
        .map_err(PkiError::Database)
}

// Marca un token como usado.
pub async fn consume_token(pool: &PgPool, token_id: Uuid) -> Result<(), PkiError> {
    db_certs::consume_enroll_token(pool, token_id)
        .await
        .map_err(PkiError::Database)
}
