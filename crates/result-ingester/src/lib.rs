//! Recibe los resultados de checks enviados por los agentes, los valida, los persiste en
//! PostgreSQL y actualiza el modelo de riesgos.
//!
//! Flujo
//! ```text
//! SubmitResultsRequest (del agente)
//!         ↓
//!   validator::validate_batch()
//!     - timestamps razonables
//!     - check_ids pertenecen al agente
//!         ↓
//!   db::results::insert_check_results()
//!         ↓
//!   scorer::ComplianceScorer::recalculate()
//!     - UPSERT en compliance_scores
//!         ↓
//!   risk_trigger::RiskTrigger::evaluate()
//!     - checks críticos fallidos → crear riesgo
//!     - checks que ahora pasan  → cerrar riesgo
//!         ↓
//!   IngestSummary → SubmitResultsResponse
//! ```
//!
//! Uso
//! ```ignore
//! use result_ingester::ResultIngester;
//! use std::sync::Arc;
//!
//! let ingester = ResultIngester::new(Arc::new(pool));
//!
//! let summary = ingester.ingest(
//!     agent_id,
//!     results,
//!     check_severities, // HashMap<String, String>: check_id → severidad
//! ).await?;
//!
//! // summary.accepted, summary.rejected, summary.rejection_reasons...
//! ```

mod ingest;
mod risk_trigger;
mod scorer;
mod validator;

pub use ingest::{IngestSummary, ResultIngester};
pub use validator::TimestampBounds;

#[derive(Debug, thiserror::Error)]
pub enum IngesterError {
    #[error("error de la base de datos: {0}")]
    Database(#[from] db::DbError),
}
