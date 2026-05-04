//! Queries para certificados de agentes y tokens de enrolamiento.
//!
//! Estas tablas no forman parte del schema original de la aplicación —
//! se crean en las migrations 002 y 003 de la PKI.

//use chrono::{DateTime, Utc, NaiveDateTime};
use chrono::NaiveDateTime;
use sqlx::PgPool;
use uuid::Uuid;

use crate::DbError;


#[derive(Debug, Clone)]
pub struct AgentCertRow {
    pub agent_id: Uuid,
    pub cert_pem: String, // Certificado en formato PEM
    pub serial: String, // Número de serie del certificado (hex). Usado para la CRL.
    pub issued_at: NaiveDateTime,
    pub revoked_at: Option<NaiveDateTime>, // `Some` si el certificado ha sido revocado
}

#[derive(Debug, Clone)]
pub struct EnrollTokenRow {
    pub id: Uuid,
    pub token_hash: String, // SHA-256 del token en claro (nunca almacenamos el token en claro)
    pub hostname_hint: Option<String>,
    pub created_at: NaiveDateTime,
    pub expires_at: NaiveDateTime,
    pub used_at: Option<NaiveDateTime>, // `Some` si el token ya fue usado
}


// Persiste el certificado de un agente tras el enrolamiento. Si el agente ya tenia un certificado,
// lo reemplaza
pub async fn store_cert(pool: &PgPool, agent_id: Uuid, cert_pem: &str, serial: &str,) -> Result<(), DbError> {
    sqlx::query!(
        r#"
        INSERT INTO agent_certs (agent_id, cert_pem, serial, issued_at)
        VALUES ($1, $2, $3, now())
        ON CONFLICT (agent_id) DO UPDATE SET
            cert_pem  = EXCLUDED.cert_pem,
            serial    = EXCLUDED.serial,
            issued_at = EXCLUDED.issued_at,
            revoked_at = NULL
        "#,
        agent_id,
        cert_pem,
        serial,
    )
    .execute(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(())
}

/// Obtiene el certificado de un agente.
pub async fn get_cert(pool: &PgPool, agent_id: Uuid) -> Result<Option<AgentCertRow>, DbError> {
    sqlx::query_as!(
        AgentCertRow,
        r#"
        SELECT agent_id, cert_pem, serial, issued_at, revoked_at
        FROM agent_certs
        WHERE agent_id = $1
        "#,
        agent_id
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)
}

// Comprueba si un número de serie está revocado. Se llama en el interceptor gRPC para cada request
// entrante.
pub async fn is_revoked(pool: &PgPool, serial: &str) -> Result<bool, DbError> {
    let row = sqlx::query!(
        "SELECT revoked_at FROM agent_certs WHERE serial = $1",
        serial
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)?;

    Ok(row.map(|r| r.revoked_at.is_some()).unwrap_or(false))
}

// Revoca el certificado de un agente.
pub async fn revoke_cert(pool: &PgPool, agent_id: Uuid) -> Result<(), DbError> {
    sqlx::query!(
        "UPDATE agent_certs SET revoked_at = now() WHERE agent_id = $1",
        agent_id
    )
    .execute(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(())
}

// Devuelve todos los certificados revocados para construir la CRL.
pub async fn list_revoked_certs(pool: &PgPool) -> Result<Vec<AgentCertRow>, DbError> {
    sqlx::query_as!(
        AgentCertRow,
        r#"
        SELECT agent_id, cert_pem, serial, issued_at, revoked_at
        FROM agent_certs
        WHERE revoked_at IS NOT NULL
        ORDER BY revoked_at DESC
        "#
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)
}

// Crea un token de enrolamiento de un solo uso. Almacena el hash SHA-256 del token, nunca en
// claro.
pub async fn save_enroll_token(pool: &PgPool, token_hash: &str, hostname_hint: Option<&str>, expires_at: NaiveDateTime,) -> Result<Uuid, DbError> {
    let row = sqlx::query!(
        r#"
        INSERT INTO enroll_tokens (token_hash, hostname_hint, expires_at)
        VALUES ($1, $2, $3)
        RETURNING id
        "#,
        token_hash,
        hostname_hint,
        expires_at,
    )
    .fetch_one(pool)
    .await
    .map_err(DbError::Query)?;

    Ok(row.id)
}

// Busca un token por su hash. No lo consume, usa `consume_enroll_token` para eso.
pub async fn find_enroll_token(pool: &PgPool, token_hash: &str,) -> Result<Option<EnrollTokenRow>, DbError> {
    sqlx::query_as!(
        EnrollTokenRow,
        r#"
        SELECT id, token_hash, hostname_hint, created_at, expires_at, used_at
        FROM enroll_tokens
        WHERE token_hash = $1
        "#,
        token_hash
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)
}

// Marca un token como usado (one-shot). Debe llamarse en la misma transaccion que el registro
// para evitar condiciones de carrera
pub async fn consume_enroll_token(pool: &PgPool, token_id: Uuid) -> Result<(), DbError> {
    sqlx::query!(
        "UPDATE enroll_tokens SET used_at = now() WHERE id = $1",
        token_id
    )
    .execute(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(())
}
