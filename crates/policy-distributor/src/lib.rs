//! Resuelve y reconstruye el `PolicyBundle` proto para cada agente.
//!
//! Combina politicas asignadas directamente al agente con las asignadas as sus grupos,
//! deduplicada, carga los detalles completos de cada politica y constriye el bundle proto listo
//! para enviar en `PollResponse`
//!
//!
//! # Uso
//! ```ignore
//! use policy_distributor::PolicyDistributor;
//! use std::sync::Arc;
//!
//! let distributor = PolicyDistributor::new(Arc::new(pool));
//!
//! // En el servicio gRPC, al recibir un PollRequest:
//! let bundle = distributor.resolve_for_agent(agent_id).await?;
//!
//! // Comparar con el hash que el agente tiene en caché:
//! if bundle.bundle_hash != req.policy_bundle_hash {
//!     // Enviar el bundle completo
//! } else {
//!     // Responder con policies_changed = false
//! }
//! ```

mod hasher;
mod resolver;

pub use hasher::bundle_hash;
pub use resolver::PolicyDistributor;

#[derive(Debug, thiserror::Error)]
pub enum DistributorError {
    #[error("error de la base de datos: {0}")]
    Database(#[from] db::DbError),
}
