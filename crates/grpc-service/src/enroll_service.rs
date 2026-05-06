//! Servicio de enrolamiento gRPC (puerto `:9001`, TLS one-way).
//!
//! Solo expone un RPC: `Enroll`. No requiere certificado de cliente porque
//! precisamente el objetivo de este servicio es emitir ese certificado.

use std::sync::Arc;

use tonic::{Request, Response, Status};

use db::PgPool;
use pki::{CertificateAuthority, enroll};
use proto::complyx::complyx_enroll_server::ComplyxEnroll;
use proto::complyx::{EnrollRequest, EnrollResponse};

#[derive(Clone)]
pub struct EnrollServiceImpl {
    pool: Arc<PgPool>,
    ca: Arc<CertificateAuthority>,
    cert_validity_days: i64,
}

impl EnrollServiceImpl {
    pub fn new(pool: Arc<PgPool>, ca: Arc<CertificateAuthority>, cert_validity_days: i64) -> Self {
        Self {
            pool,
            ca,
            cert_validity_days,
        }
    }
}

#[tonic::async_trait]
impl ComplyxEnroll for EnrollServiceImpl {
    async fn enroll(
        &self,
        request: Request<EnrollRequest>,
    ) -> Result<Response<EnrollResponse>, Status> {
        let req = request.into_inner();

        // Obtener la IP del peer para registrar el agente. Si lo pusiese detrás de un proxy tendría
        // q leer X-Forwarded-For. De todas formas, ya veré como lo hago para un despliegue bueno
        let remote_ip = "0.0.0.0".to_string(); // El grpc-service no tiene acceso directo a la IP del peer en tonic sin extensiones adicionales

        tracing::info!(
            hostname = %req.hostname,
            os_name  = %req.os_name,
            "solicitud de enrolamiento recibida"
        );

        let enroll_req = enroll::EnrollRequest {
            token: req.token,
            csr_pem: req.csr_pem,
            hostname: req.hostname,
            os_name: req.os_name,
            os_version: req.os_version,
            remote_ip,
        };

        let result =
            enroll::process_enroll(&self.pool, &self.ca, &enroll_req, self.cert_validity_days)
                .await
                .map_err(tonic::Status::from)?;

        Ok(Response::new(EnrollResponse {
            cert_pem: result.cert_pem,
            ca_cert_pem: result.ca_cert_pem,
        }))
    }
}
