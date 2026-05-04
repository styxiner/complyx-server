//! # pki
//!
//! PKI (Public Key Infrastructure) interna del servidor Complyx.
//!
//! Gestiona el ciclo de vida completo de los certificados de los agentes:
//!
//! - **`ca`** — CA raíz interna: generación, persistencia y firma de CSRs.
//! - **`token`** — Tokens de enrolamiento de un solo uso.
//! - **`enroll`** — Flujo completo de enrolamiento: valida token, firma CSR, registra agente.
//! - **`revoke`** — Revocación de certificados y listado de revocados.
//! - **`store`** — Fachada sobre `db::certs` para acceso a la BD.
//!
//! ## Uso típico
//!
//! ```ignore
//! use pki::{CertificateAuthority, enroll, token, revoke};
//!
//! // Al arrancar el servidor:
//! let ca = CertificateAuthority::load_or_create("/var/lib/complyx/pki").await?;
//!
//! // El admin genera un token:
//! let tok = token::generate(&pool, Some("web-01"), 24).await?;
//! println!("Token: {}", tok.token);
//!
//! // El agente se enrola:
//! let result = enroll::process_enroll(&pool, &ca, &req, 365).await?;
//!
//! // Revocar un agente comprometido:
//! revoke::revoke_agent_cert(&pool, agent_id).await?;
//! ```

pub mod ca;
pub mod enroll;
pub mod revoke;
pub mod store;
pub mod token;

pub use ca::CertificateAuthority;

#[derive(Debug, thiserror::Error)]
pub enum PkiError {
    #[error("token de enrolamiento inválido")]
    TokenInvalid,

    #[error("token de enrolamiento ya utilizado")]
    TokenAlreadyUsed,

    #[error("token de enrolamiento expirado")]
    TokenExpired,

    #[error("agente {0} no encontrado")]
    AgentNotFound(uuid::Uuid),

    #[error("CSR inválido: {0}")]
    CsrParse(String),

    #[error("firma del CSR inválida: {0}")]
    CsrSignatureInvalid(String),

    #[error("error generando certificado: {0}")]
    CertGeneration(String),

    #[error("error de I/O en '{path}': {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("error de base de datos: {0}")]
    Database(#[from] db::DbError),
}

// Convierte `PkiError` en un código de estado gRPC para los servicios. Se usa en `grpc-service`
// para devolver respuestas de error correctas.
impl From<PkiError> for tonic::Status {
    fn from(e: PkiError) -> Self {
        match e {
            PkiError::TokenInvalid
            | PkiError::TokenAlreadyUsed
            | PkiError::TokenExpired => tonic::Status::unauthenticated(e.to_string()),

            PkiError::CsrParse(_)
            | PkiError::CsrSignatureInvalid(_) => tonic::Status::invalid_argument(e.to_string()),

            PkiError::AgentNotFound(_) => tonic::Status::not_found(e.to_string()),

            PkiError::CertGeneration(_)
            | PkiError::Io { .. }
            | PkiError::Database(_) => {
                tracing::error!(error = %e, "error interno en PKI");
                tonic::Status::internal("error interno del servidor")
            }
        }
    }
}
