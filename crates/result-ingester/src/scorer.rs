//! Calculo y persistencia de scores de cumplimiento
//!
//! Tras insertar un lote de resultados, el scorer recalcula el porcentaje de complimiento de cada
//! elemento de politica para el agente y lo persiste en `compliance_scores` con un UPSERT.
//!
//! El score es un numero entre 0.0 y 100.0 que representa el porcentaje de checks pasados sobre el
//! total de checks del elemento, usando siempre el resultado mas reciente de cada check.

use std::sync::Arc;

use uuid::Uuid;

use db::PgPool;
use db::results as db_results;

use crate::IngesterError;

#[derive(Clone)]
pub struct ComplianceScorer {
    pool: Arc<PgPool>,
}

impl ComplianceScorer {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    // Recalcula los scores de cumplimiento del agente tras insertar nuevos resultados.
    //
    // Usa la query UPSERT de `db::results::upsert_compliance_scores` que calcula los scores en una
    // sola query con DISTINCT ON para tomar el resultado mas reciente de cada check.
    //
    // Devuelve el numero de elementos de una politica actualizados
    pub async fn recalculate(&self, agent_id: Uuid) -> Result<usize, IngesterError> {
        let scores = db_results::upsert_compliance_scores(&self.pool, agent_id)
            .await
            .map_err(IngesterError::Database)?;

        let updated = scores.len();

        // pequeño resumen: score global del agente (media de todos los elementos)
        if !scores.is_empty() {
            let global_score: f64 =
                scores.iter().map(|s| s.score).sum::<f64>() / scores.len() as f64;

            let total_checks: i64 = scores.iter().map(|s| s.total_checks).sum();
            let passed_checks: i64 = scores.iter().map(|s| s.passed_checks).sum();

            tracing::info!(
                agent_id = %agent_id,
                elements_updated = updated,
                total_checks,
                passed_checks,
                global_score = format!("{:.1}", global_score),
                "scores de cumplimiento actualizados"
            );

            // Alerta si el score global cae por debajo del 80%
            if global_score < 80.0 {
                tracing::warn!(
                    agent_id = %agent_id,
                    global_score = format!("{:.1}", global_score),
                    "agente por debajo del umbral de cumplimiento (80%)"
                );
            }
        }

        Ok(updated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_calculation_logic() {
        // Verificar la lógica de score manualmente
        let total = 10i64;
        let passed = 8i64;
        let score = (passed as f64 / total as f64) * 100.0;
        assert!((score - 80.0).abs() < f64::EPSILON);
    }

    #[test]
    fn zero_checks_score() {
        let total = 0i64;
        let score = if total > 0 { 100.0f64 } else { 0.0f64 };
        assert_eq!(score, 0.0);
    }
}
