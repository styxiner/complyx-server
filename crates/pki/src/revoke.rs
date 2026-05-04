//! Revocación de certificados y generación de CRL.
//!
//! ## Flujo de revocación
//!
//! 1. El administrador llama a `revoke_agent_cert()`.
//! 2. Se marca `revoked_at` en `agent_certs`.
//! 3. El interceptor gRPC llama a `is_cert_revoked()` en cada request para
//!    rechazar agentes revocados con `Status::Unauthenticated`.
//!
//! ## CRL (Certificate Revocation List)
//!
//! `generate_crl()` produce una CRL en formato DER que puede servirse a clientes
//! que necesiten verificar el estado de revocación fuera del servidor.
//! En el flujo normal del servidor, la verificación se hace directamente
//! contra la BD con `is_cert_revoked()` — más rápido que parsear la CRL.

use sqlx::PgPool;
use uuid::Uuid;

use db::certs as db_certs;

use crate::PkiError;

// Revoca el certificado de un agente.
//
// Tras la revocación, el próximo poll del agente recibirá `Unauthenticated` del interceptor gRPC y
// dejara de comunicarse con el servidor.
//
// # Errores
//
// * `PkiError::AgentNotFound` si el agente no tiene certificado en la BD.
// * `PkiError::Database` ante errores de acceso a la BD.
pub async fn revoke_agent_cert(pool: &PgPool, agent_id: Uuid) -> Result<(), PkiError> {
    // Verificar que el agente tiene certificado antes de revocar
    let cert = db_certs::get_cert(pool, agent_id)
        .await
        .map_err(PkiError::Database)?
        .ok_or(PkiError::AgentNotFound(agent_id))?;

    if cert.revoked_at.is_some() {
        tracing::warn!(
            agent_id = %agent_id,
            revoked_at = ?cert.revoked_at,
            "certificado ya estaba revocado"
        );
        // No es un error: revocar dos veces es idempotente
        return Ok(());
    }

    db_certs::revoke_cert(pool, agent_id)
        .await
        .map_err(PkiError::Database)?;

    tracing::info!(
        agent_id = %agent_id,
        serial   = %cert.serial,
        "certificado revocado"
    );

    Ok(())
}

// Comprueba si el certificado identificado por `serial` está revocado.
//
// Se llama desde el interceptor gRPC en cada request entrante de un agente. La consulta usa el
// indice `idx_agent_certs_serial` para ser mas eficiente
pub async fn is_cert_revoked(pool: &PgPool, serial: &str) -> Result<bool, PkiError> {
    db_certs::is_revoked(pool, serial)
        .await
        .map_err(PkiError::Database)
}

// Devuelve los seriales de todos los certificados revocados.
//
// Útil para construir una CRL o para auditoría.
pub async fn list_revoked_serials(pool: &PgPool) -> Result<Vec<RevokedCert>, PkiError> {
    let rows = db_certs::list_revoked_certs(pool)
        .await
        .map_err(PkiError::Database)?;

    Ok(rows
        .into_iter()
        .map(|r| RevokedCert {
            agent_id: r.agent_id,
            serial: r.serial,
            revoked_at: r.revoked_at.unwrap(), // solo llegan filas con revoked_at
        })
        .collect())
}

// Información de un certificado revocado.
#[derive(Debug, Clone)]
pub struct RevokedCert {
    pub agent_id: Uuid,
    pub serial: String,
    pub revoked_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoked_cert_fields() {
        let now = chrono::Utc::now();
        let r = RevokedCert {
            agent_id: Uuid::new_v4(),
            serial: "deadbeef".into(),
            revoked_at: now,
        };
        assert_eq!(r.serial, "deadbeef");
    }
}
