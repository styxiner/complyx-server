//! Construye las configuraciones TLS para los dos servidores gRPC de Complyx:
//!
//! * Puerto principal (9000): mTLS bidireccional. Los agentes deben presentar su certificado de
//! cliente firmado por la CA interna.
//! * Puerto de registro (9001): TLS unidireccional. No requiere certificado de cliente porque el
//! agente no tiene uno todavia.
//!
//! Ademas expone `is_cert_revoked()` para que el interceptor gRPC pueda verificar si el certificado
//! presentado por el agente esta revocado.

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, private_key};
use tonic::transport::{Certificate, Identity, ServerTlsConfig};
use uuid::Uuid;

use db::PgPool;
use pki::revoke;

#[derive(Debug, thiserror::Error)]
pub enum GrpcPkiError {
    #[error("error de E/S leyendo certificados en '{path}': '{source}'")]
    Io {
        path: String,

        #[source]
        source: std::io::Error,
    },

    #[error("no se encontro ningun certificado en '{path}'")]
    NoCertificate { path: String },

    #[error("no se encontro ninguna clave privada en '{path}'")]
    NoPrivateKey { path: String },

    #[error("PEM invalido en '{path}': {reason}")]
    InvalidPem { path: String, reason: String },

    #[error("error en la base de datos: {0}")]
    Database(#[from] db::DbError),

    #[error("error de la PKI: {0}")]
    Pki(#[from] pki::PkiError),
}

// Configuracion TLS para el puerto principal (9000) con mTLS.
//
// Requiere 3 ficheros en `ca_dir`:
// * `server.crt`: certificado del servidor (firmado por la CA interna)
// * `server.key`: clave privada del servidor
// * `ca.crt`: certificado raiz de la CA (para verificar los agentes)
//
// El certificado del servidor puede ser el mismo que el de la CA si el servidor se autentica con su
// propio cert raiz, o un certificado separado emitido por la CA.
pub async fn build_mtls_config(ca_dir: impl AsRef<Path>) -> Result<ServerTlsConfig, GrpcPkiError> {
    let dir = ca_dir.as_ref();

    let server_cert_pem = read_file(dir.join("server.crt")).await?;
    let server_key_pem = read_file(dir.join("servr.key")).await?;
    let ca_cert_pem = read_file(dir.join("ca.crt")).await?;

    validate_cert_pem(
        &server_cert_pem,
        &dir.join("server.crt").display().to_string(),
    )?;
    validate_key_pem(
        &server_key_pem,
        &dir.join("server.key").display().to_string(),
    )?;
    validate_cert_pem(&ca_cert_pem, &dir.join("ca.crt").display().to_string())?;

    // Ponemos como Identiy a la asociacion del servidor con su clave privada.
    let identity = Identity::from_pem(&server_cert_pem, &server_key_pem);

    // CA raiz para verificar los certificados de cliente (mTLS)
    let client_ca = Certificate::from_pem(&ca_cert_pem);

    let config = ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(client_ca);

    tracing::info!(
        ca_dir = %dir.display(),
        "configuracion mTLS del servidor construida"
    );

    Ok(config)
}

// Verifica si el certificado con el serial dado esta revocado. Se llama desde el interceptor gRPC
// del puerto principal en cada request entrante, tras exceder el serial del certificado de cliente
// del handshake TLS.
//
// La consulta usa el indice `idx_agent_certs_serial` para optimizar tiempos.
pub async fn is_cert_revoked(pool: &PgPool, serial: &str) -> Result<bool, GrpcPkiError> {
    revoke::is_cert_revoked(pool, serial)
        .await
        .map_err(GrpcPkiError::Pki)
}

async fn read_file(path: impl AsRef<Path>) -> Result<Vec<u8>, GrpcPkiError> {
    let path = path.as_ref();

    tokio::fs::read(path).await.map_err(|e| GrpcPkiError::Io {
        path: path.display().to_string(),
        source: e,
    })
}

fn validate_cert_pem(pem: &[u8], path: &str) -> Result<(), GrpcPkiError> {
    let mut cursor = std::io::Cursor::new(pem);
    let parsed: Vec<_> = certs(&mut cursor).collect();

    if parsed.is_empty() || parsed.iter().all(|c| c.is_err()) {
        return Err(GrpcPkiError::NoCertificate {
            path: path.to_string(),
        });
    }
    if let Some(Err(e)) = parsed.into_iter().find(|c| c.is_err()) {
        return Err(GrpcPkiError::InvalidPem {
            path: path.to_string(),
            reason: e.to_string(),
        });
    }
    Ok(())
}

fn validate_key_pem(pem: &[u8], path: &str) -> Result<(), GrpcPkiError> {
    let mut cursor = std::io::Cursor::new(pem);
    match private_key(&mut cursor) {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(GrpcPkiError::NoPrivateKey {
            path: path.to_string(),
        }),
        Err(e) => Err(GrpcPkiError::InvalidPem {
            path: path.to_string(),
            reason: e.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_cert_pem_rejects_empty() {
        let result = validate_cert_pem(b"not pem", "/test/cert.pem");
        assert!(result.is_err());
    }

    #[test]
    fn validate_key_pem_rejects_empty() {
        let result = validate_key_pem(b"not pem", "/test/key.pem");
        assert!(result.is_err());
    }
}
