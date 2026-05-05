//! Orquestacion del flujo completo de ingesta de resultados.
//!
//! Orden de operaciones
//!
//! Validar (timestamp + autorizacion de check_ids)
//! Persistir los validos en `check_results`
//! Recalcular scores de cumplimiento
//! Evaluar disparadores de riesgo
//! Devolver resumen al servicio gRPC

use std::collections::HashMap;
use std::sync::Arc;

use uuid::Uuid;

use db::PgPool;
use db::results as db_results;
use proto::CheckResult;

use crate::scorer::ComplianceScorer;
use crate::risk_trigger::RiskTrigger;
use crate::validator::{Self, TimestampBounds};
use crate::IngesterError;

#[derive(Debug, Default)]
pub struct IngestSummary {
    pub accepted: usize,
    pub rejected: usize,
    pub rejection_reasons: HashMap<String, String>,
    pub scores_updated: usize,
    pub risks_created: usize,
    pub risks_closed: usize,
}

#[derive(Clone)]
pub struct ResultIngester {
    pool: Arc<PgPool>,
    scorer: ComplianceScorer,
    risk_trigger: RiskTrigger,
    timestamp_bounds: Arc<TimestampBounds>,
}

impl ResultIngester {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self {
            scorer: ComplianceScorer::new(Arc::clone(&pool)),
            risk_trigger: RiskTrigger::new(Arc::clone(&pool)),
            pool,
            timestamp_bounds: Arc::new(TimestampBounds::default()),
        }
    }

    // Ejecuta el flujo completo de ingesta para un agente.
    //
    // Argumentos
    // * `agent_id`: UUID del agente (extraido del certificado mTLS en el interceptor)
    // * `results`: resultados del `SubmitResultsRequest`
    // * `check_severities`: mapa check_id con severidad para el `risk_trigger`. Puede estar vacio:
    // en ese caso no se crean riesgos automaticamente.
    
    pub async fn ingest(&self, agent_id: Uuid, results: Vec<CheckResult>, check_severities: HashMap<String, String>) -> Result<IngestSummary, IngesterError> {
        let pool = &*self.pool;
        let mut summary = IngestSummary::default();

        if results.is_empty() {
            return Ok(summary);
        }

        tracing::info!(
            agent_id = %agent_id,
            result_count = results.len(),
            "iniciando ingesta de resultados"
        );

        // Validar
        let report = validator::validate_batch(
            pool,
            agent_id,
            &results,
            &self.timestamp_bounds,
        )
        .await?

        summary.rejected = report.rejected.len();


        for r in &report.rejected {
            summary.rejection_reasons.insert(r.check_id.clone(), r.reason.clone());
            tracing::warn!(
                agent_id = %agent_id,
                check_id = %r.check_id,
                reason = %r.reason,
                "resultado rechazado"
            );
        }

        if report.valid.is_empty() {
            tracing::warn!(
                agent_id = %agent_id,
                "ningun resultado valido en el lote"
            );

            return Ok(summary);
        }

        // Persistir los validos
        let to_insert: Vec<db_results::InsertCheckResult> = report
            .valid
            .iter()
            .map(|r| db_results::InsertCheckResult {
                agent_id,
                check_id: r.check_id.parse().unwrap(), // ya validado como UUID
                passed: r.passed,
                detail: r.detail.clone(),
                actual_value: r.actual_value.clone(),
                expected_value: r.expected_value.clone(),
                executed_at_unix: r.executed_at,
            })
            .collect();
 
        let inserted = db_results::insert_check_results(pool, &to_insert)
            .await
            .map_err(IngesterError::Database)?;
 
        summary.accepted = inserted;
 
        tracing::debug!(
            agent_id = %agent_id,
            inserted,
            "resultados persistidos en BD"
        );

        // Recalcular scores en paralelo con el risk trigger no es posible porque ambos necesitan
        // los resultados ya insertados: scorer primero.
        summary.scores_updated = self.scorer.recalculate(agent_id).await?;

        // Disparador de riesgos
        let risk_summary = self.risk_trigger
            .evaluate(agent_id, &report.valid, &check_severities)
            .await?;
 
        summary.risks_created = risk_summary.created;
        summary.risks_closed = risk_summary.closed;
 
        tracing::info!(
            agent_id = %agent_id,
            accepted = summary.accepted,
            rejected = summary.rejected,
            scores_updated = summary.scores_updated,
            risks_created = summary.risks_created,
            risks_closed = summary.risks_closed,
            "ingesta completada"
        );

        Ok(summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
 
    #[test]
    fn ingest_summary_default_is_zeroed() {
        let s = IngestSummary::default();
        assert_eq!(s.accepted, 0);
        assert_eq!(s.rejected, 0);
        assert!(s.rejection_reasons.is_empty());
    }
}

