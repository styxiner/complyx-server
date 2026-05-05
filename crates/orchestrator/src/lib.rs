//! Estado en memoria de los agentes y monitor de heartbeats
//!
//! El `Orchestrator` es la fuente de verdad sobre que agentes estan conectados. PostgreSQL es la
//! fuente de verdad historica: Se actualiza en cada poll/heartbeat real, pero no en cada tick del
//! monitor.
//!
//! ## Ciclo de vida de un agente en el Orchestrator:
//!
//! ```text
//! Registro -> primer poll/heartbeat -> update_heartbeat() -> Online
//!                                                             ↓
//!                                                 Sin actividad > offline_timeout
//!                                                             ↓
//!                                             monitor -> mark_offline() -> Offline
//!                                                             ↓
//!                                                 nuevo poll/heartbeat -> Online
//!                                                             ↓
//! ```
//!
//! ## Uso
//! ```ignore
//! use orchestrator::{Orchestrator, heartbeat};
//! use tokio::sync::watch;
//!
//! let orc = Orchestrator::new(300); // offline tras 5 min sin heartbeat
//!
//! let (shutdown_tx, shutdown_rx) = watch::channel(false);
//! heartbeat::spawn_monitor(
//!     orc.clone(),
//!     std::time::Duration::from_secs(60),
//!     shutdown_rx,
//! );
//!
//! // En el servicio gRPC, tras recibir poll o heartbeat:
//! orc.update_heartbeat(agent_id);
//! orc.update_policy_hash(agent_id, bundle_hash);
//!
//! // Para consultar el estado:
//! let online = orc.online_count();
//! let hash = orc.get_policy_hash(agent_id);
//! ```

pub mod heartbeat;
mod state;

pub use state::{AgentState, AgentStatus, Orchestrator};

// Error del crate `orchestrator`. Solo hay errores de base de datos al sincronizar con PostgreSQL.
#[derive(Debug, thiserror::Error)]
pub enum OrchestratorError {
    #[error("error de la base de datos: {0}")]
    Database(#[from] db::DbError),
}
