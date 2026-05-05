//! Flujo completo de enrolamiento de un agente.
//!
//! Orquesta los pasos de validación, firma de certificado y registro en BD
//! dentro de una única transacción lógica:
//!
//! 1. Validar y consumir el token de un solo uso.
//! 2. Crear o actualizar el agente en `agents`.
//! 3. Firmar el CSR con la CA interna.
//! 4. Persistir el certificado emitido en `agent_certs`.
//! 5. Devolver el certificado y el certificado raíz de la CA al agente.

use sqlx::PgPool;

use db::{agents as db_agents, certs as db_certs};

use ipnetwork::IpNetwork;

use crate::PkiError;
use crate::ca::CertificateAuthority;
use crate::token;

#[derive(Debug, Clone)]
pub struct EnrollRequest {
    pub token: String, // Token de un solo uso generado por el administrador.
    pub csr_pem: String,
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub remote_ip: String,
}

#[derive(Debug)]
pub struct EnrollResult {
    pub agent_id: uuid::Uuid, // UUID del agente en la BD (nuevo o existente si es re-enrolamiento).
    pub cert_pem: String,
    pub ca_cert_pem: String, // Certificado raiz de la CA en formato PEM. El agente lo guarda como
                             // `ca.crt` para verificar el servidor en mTLS
}

// Ejecuta el flujo completo de enrolamiento.
//
// # Errores
//
// * `PkiError::TokenInvalid` / `TokenAlreadyUsed` / `TokenExpired` — token inválido.
// * `PkiError::CsrParse` — el CSR no es válido.
// * `PkiError::CsrSignatureInvalid` — la firma del CSR no es válida.
// * `PkiError::CertGeneration` — error al firmar el certificado.
// * `PkiError::Database` — error al acceder a la BD.
pub async fn process_enroll(
    pool: &PgPool,
    ca: &CertificateAuthority,
    req: &EnrollRequest,
    cert_validity_days: i64,
) -> Result<EnrollResult, PkiError> {
    tracing::info!(
        hostname = %req.hostname,
        os_name  = %req.os_name,
        ip       = %req.remote_ip,
        "procesando solicitud de enrolamiento"
    );

    // 1. Validar y consumir el token
    // Si falla aquí, no se ha modificado nada en la BD todavía
    let _token_row = token::validate_and_consume(pool, &req.token).await?;

    // 2. Registrar o actualizar el agente en BD
    // upsert_agent usa la IP como clave de deduplicación para manejar re-enrolamientos
    let agent_id = db_agents::upsert_agent(
        pool,
        &db_agents::UpsertAgentData {
            ip: req
                .remote_ip
                .parse::<IpNetwork>()
                .map_err(|e| PkiError::InvalidIp(e.to_string()))?,
            hostname: Some(req.hostname.clone()),
            os_name: Some(req.os_name.clone()),
            os_version: Some(req.os_version.clone()),
        },
    )
    .await
    .map_err(PkiError::Database)?;

    tracing::debug!(agent_id = %agent_id, "agente registrado/actualizado en BD");

    // 3. Firmar el CSR con la CA interna
    let (cert_pem, serial) = ca
        .sign_csr(&req.csr_pem, &req.hostname, cert_validity_days)
        .await?;

    // 4. Persistir el certificado emitido
    // Si el agente ya tenía un certificado (re-enrolamiento), se reemplaza
    db_certs::store_cert(pool, agent_id, &cert_pem, &serial)
        .await
        .map_err(PkiError::Database)?;

    tracing::info!(
        agent_id = %agent_id,
        hostname = %req.hostname,
        serial   = %serial,
        "enrolamiento completado"
    );

    Ok(EnrollResult {
        agent_id,
        cert_pem,
        ca_cert_pem: ca.ca_cert_pem().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enroll_request_fields_accessible() {
        let req = EnrollRequest {
            token: "tok".into(),
            csr_pem: "csr".into(),
            hostname: "host".into(),
            os_name: "Linux".into(),
            os_version: "6.8".into(),
            remote_ip: "10.0.0.1".into(),
        };
        assert_eq!(req.hostname, "host");
        assert_eq!(req.remote_ip, "10.0.0.1");
    }
}
