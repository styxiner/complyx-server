//! Servicio principal gRPC (puerto 9000, mTLS).
//!
//! Expone tres RPCs a los agentes registrados:
//! * `PollPolicies`: obtiene el bundle de politicas del agente.
//! * `SubmitResults`: recibe y persiste los resultados de checks.
//! * `HeartBeat`: actualiza el timestamp de la ultima conexion.
use std::collections::HashMap;
use std::sync::Arc;

use tonic::{Request, Response, Status};
use uuid::Uuid;

use db::PgPool;
use orchestrator::Orchestrator;
use policy_distributor::PolicyDistributor;
use proto::complyx::complyx_agent_server::ComplyxAgent;
use proto::complyx::{
    HeartbeatRequest, HeartbeatResponse, PollRequest, PollResponse, SubmitResultsRequest,
    SubmitResultsResponse,
};
use result_ingester::ResultIngester;

use crate::interceptor::AgentId;

#[derive(Clone)]
pub struct AgentServiceImpl {
    pool: Arc<PgPool>,
    orchestrator: Orchestrator,
    distributor: PolicyDistributor,
    ingester: ResultIngester,
}

impl AgentServiceImpl {
    pub fn new(
        pool: Arc<PgPool>,
        orchestrator: Orchestrator,
        distributor: PolicyDistributor,
        ingester: ResultIngester,
    ) -> Self {
        Self {
            pool,
            orchestrator,
            distributor,
            ingester,
        }
    }
}

#[tonic::async_trait]
impl ComplyxAgent for AgentServiceImpl {
    // Poll de políticas: devuelve el bundle si ha cambiado desde el último poll.
    async fn poll_policies(
        &self,
        request: Request<PollRequest>,
    ) -> Result<Response<PollResponse>, Status> {
        let agent_id = extract_agent_id(&request)?;
        let req = request.into_inner();

        tracing::debug!(
            agent_id = %agent_id,
            client_hash = %req.policy_bundle_hash,
            "PollRequest recibido"
        );

        // Actualizar heartbeat y latest_connection
        self.orchestrator.update_heartbeat(agent_id);
        if let Err(e) = db::agents::update_latest_connection(&self.pool, agent_id).await {
            tracing::warn!(agent_id = %agent_id, error = %e, "no se pudo actualizar latest_connection");
        }

        // Resolver el bundle actual del agente
        let bundle = self
            .distributor
            .resolve_for_agent(agent_id)
            .await
            .map_err(|e| {
                tracing::error!(agent_id = %agent_id, error = %e, "error resolviendo políticas");
                Status::internal("error resolviendo políticas")
            })?;

        // Comparar con el hash que el agente tiene en caché
        if bundle.bundle_hash == req.policy_bundle_hash {
            tracing::debug!(agent_id = %agent_id, "políticas sin cambios");
            return Ok(Response::new(PollResponse {
                policies_changed: false,
                bundle: None,
            }));
        }

        // Actualizar el hash en el orchestrator
        self.orchestrator
            .update_policy_hash(agent_id, bundle.bundle_hash.clone());

        tracing::info!(
            agent_id = %agent_id,
            bundle_hash = %bundle.bundle_hash,
            policies = bundle.policies.len(),
            "enviando bundle actualizado"
        );

        Ok(Response::new(PollResponse {
            policies_changed: true,
            bundle: Some(bundle),
        }))
    }

    // Recibe los resultados de checks del agente y los persiste.
    async fn submit_results(
        &self,
        request: Request<SubmitResultsRequest>,
    ) -> Result<Response<SubmitResultsResponse>, Status> {
        let agent_id = extract_agent_id(&request)?;
        let req = request.into_inner();

        // Validar que el agent_id del request coincide con el del certificado
        if let Ok(req_agent_id) = req.agent_id.parse::<Uuid>() {
            if req_agent_id != agent_id {
                tracing::warn!(
                    cert_agent_id = %agent_id,
                    req_agent_id  = %req_agent_id,
                    "agent_id del request no coincide con el certificado"
                );
                return Err(Status::permission_denied(
                    "agent_id no coincide con el certificado de cliente",
                ));
            }
        }

        tracing::debug!(
            agent_id = %agent_id,
            result_count = req.results.len(),
            "SubmitResultsRequest recibido"
        );

        // Obtener las severidades de los checks para el risk_trigger. En esta implementacion se
        // pasa un mapa vacio; En la implementacion completa se obttendria el bundle en cache
        let check_severities: HashMap<String, String> = HashMap::new();

        let summary = self
            .ingester
            .ingest(agent_id, req.results, check_severities)
            .await
            .map_err(|e| {
                tracing::error!(agent_id = %agent_id, error = %e, "error en ingesta");
                Status::internal("error procesando resultados")
            })?;

        let accepted = summary.accepted > 0 || summary.rejected == 0;

        Ok(Response::new(SubmitResultsResponse {
            accepted,
            accepted_count: summary.accepted as u32,
            rejected_count: summary.rejected as u32,
        }))
    }

    // Heartbeat: actualiza el timestamp de última conexión del agente.
    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        let agent_id = extract_agent_id(&request)?;

        self.orchestrator.update_heartbeat(agent_id);
        if let Err(e) = db::agents::update_latest_connection(&self.pool, agent_id).await {
            tracing::warn!(agent_id = %agent_id, error = %e, "error actualizando latest_connection");
        }

        let server_timestamp = chrono::Utc::now().timestamp();

        // Indicar al agente si debe renovar su certificado (menos de 30 días)
        let cert_renewal_required = check_cert_renewal_needed(&self.pool, agent_id).await;

        tracing::debug!(
            agent_id = %agent_id,
            cert_renewal_required,
            "heartbeat procesado"
        );

        Ok(Response::new(HeartbeatResponse {
            server_timestamp,
            cert_renewal_required,
        }))
    }
}

// Extrae el `AgentId` inyectado por el interceptor en las extensiones del request.
fn extract_agent_id<T>(request: &Request<T>) -> Result<Uuid, Status> {
    request
        .extensions()
        .get::<AgentId>()
        .map(|id| id.0)
        .ok_or_else(|| {
            // Nunca debería ocurrir si el interceptor está correctamente configurado
            tracing::error!("AgentId no presente en las extensiones del request");
            Status::internal("error de autenticación interno")
        })
}

// Comprueba si el certificado del agente expira en menos de 30 días.
async fn check_cert_renewal_needed(pool: &Arc<PgPool>, agent_id: Uuid) -> bool {
    let cert = match db::certs::get_cert(pool, agent_id).await {
        Ok(Some(c)) => c,
        _ => return false,
    };

    // Parsear el certificado para ver cuándo expira
    if let Ok(pem) = pem::parse(&cert.cert_pem) {
        if let Ok((_, parsed)) = x509_parser::parse_x509_certificate(pem.contents()) {
            let expiry = parsed.validity().not_after.timestamp();
            let days_remaining = (expiry - chrono::Utc::now().timestamp()) / 86_400;
            return days_remaining < 30;
        }
    }
    false
}
