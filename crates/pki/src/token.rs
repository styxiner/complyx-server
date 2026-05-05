//! Tokens de enrolamiento de un solo uso.
//!
//! ## Flujo
//!
//! 1. El administrador llama a `generate()` → recibe el token en claro (solo esta vez).
//! 2. El servidor almacena el hash SHA-256 del token en `enroll_tokens`.
//! 3. El agente envía el token en claro en `EnrollRequest`.
//! 4. El servidor llama a `validate_and_consume()` → hashea el token recibido,
//!    busca en BD, verifica que no esté usado ni expirado, y lo marca como usado.
//!
//! El token en claro nunca se almacena en la BD ni en los logs.

use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use db::certs as db_certs;

use crate::PkiError;

#[derive(Debug)]
pub struct GeneratedToken {
    pub token: String, // Token en claro. Se muestra una sola vez y nunca se almacena.
    pub hostname_hint: Option<String>, // Hostname al que está destinado (informativo, no se valida en el enrolamiento).
    pub expires_at: DateTime<Utc>,
}

// Genera un token de enrolamiento de un solo uso y lo persiste en la BD.
//
// # Argumentos
//
// * `hostname_hint` — hostname del endpoint al que está destinado (solo informativo).
// * `expiry_hours` — cuántas horas es válido el token (defecto: 24h).
pub async fn generate(
    pool: &PgPool,
    hostname_hint: Option<&str>,
    expiry_hours: i64,
) -> Result<GeneratedToken, PkiError> {
    let token = format!(
        "{}{}",
        hex::encode(Uuid::new_v4().as_bytes()),
        hex::encode(Uuid::new_v4().as_bytes())
    );

    let token_hash = hash_token(&token);
    let expires_at = Utc::now() + Duration::hours(expiry_hours);

    db_certs::save_enroll_token(pool, &token_hash, hostname_hint, expires_at.naive_utc())
        .await
        .map_err(PkiError::Database)?;

    tracing::info!(
        hostname_hint = ?hostname_hint,
        expires_at = %expires_at,
        "token de enrolamiento generado"
    );

    Ok(GeneratedToken {
        token,
        hostname_hint: hostname_hint.map(|s| s.to_string()),
        expires_at,
    })
}

// Valida y consume un token de enrolamiento.
//
// Busca el token en la BD por su hash, verifica que:
// - Existe en la BD.
// - No ha sido usado previamente.
// - No ha expirado.
//
// Si todo es correcto, lo marca como usado (one-shot) y devuelve los metadatos.
//
// # Errores
//
// * `PkiError::TokenInvalid` — el token no existe.
// * `PkiError::TokenAlreadyUsed` — el token ya fue consumido.
// * `PkiError::TokenExpired` — el token expiró.
pub async fn validate_and_consume(
    pool: &PgPool,
    token_plain: &str,
) -> Result<db::certs::EnrollTokenRow, PkiError> {
    let token_hash = hash_token(token_plain);

    let row = db_certs::find_enroll_token(pool, &token_hash)
        .await
        .map_err(PkiError::Database)?
        .ok_or(PkiError::TokenInvalid)?;

    if row.used_at.is_some() {
        tracing::warn!(
            token_id = %row.id,
            used_at = ?row.used_at,
            "intento de reutilizar token de enrolamiento ya consumido"
        );
        return Err(PkiError::TokenAlreadyUsed);
    }

    if Utc::now().naive_utc() > row.expires_at {
        tracing::warn!(
            token_id = %row.id,
            expired_at = %row.expires_at,
            "intento de usar token de enrolamiento expirado"
        );
        return Err(PkiError::TokenExpired);
    }

    // Consumir el token: marcar como usado
    db_certs::consume_enroll_token(pool, row.id)
        .await
        .map_err(PkiError::Database)?;

    tracing::info!(
        token_id = %row.id,
        hostname_hint = ?row.hostname_hint,
        "token de enrolamiento consumido"
    );

    Ok(row)
}

// Calcula el hash SHA-256 del token y lo devuelve en hex. Esta es la funcion que garantiza que el
// token en claro nunca toque la bbdd
// Esta es la función que garantiza que el token en claro nunca toca la BD.
fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_token_is_deterministic() {
        let h1 = hash_token("mi-token-secreto");
        let h2 = hash_token("mi-token-secreto");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_token_is_hex_64_chars() {
        // SHA-256 = 32 bytes = 64 hex chars
        let h = hash_token("test");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn different_tokens_have_different_hashes() {
        assert_ne!(hash_token("token-a"), hash_token("token-b"));
    }

    #[test]
    fn generated_token_is_long_enough() {
        // 2 × UUID (32 hex chars cada uno) = 64 chars
        let token = format!(
            "{}{}",
            hex::encode(Uuid::new_v4().as_bytes()),
            hex::encode(Uuid::new_v4().as_bytes())
        );
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
