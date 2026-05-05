//! Validacion de resultados antes de persistirlos
//!
//! Dos validaciones principales:
//! * Autorizacion: el `check_id` debe permanecer a una politica asignada al agente (directamente o
//! por grupo). Evita que un agente comprometido inyecte resultados de checks que no le
//! corresponden.
//! * Timestamp: el `executed_at` no puede ser del futuro ni demasiado antigui. Evita replay
//! attacks (idea de p y flop) y resultados con timestamps erroneos.

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use db::PgPool;
use db::results as db_results;
use proto::CheckResult;

use crate::IngesterError;

pub struct TimestampBounds {
    pub max_future_secs: i64,
    pub max_past_secs: i64,
}

impl Default for TimestampBounds {
    fn default() -> Self {
        Self {
            max_future_secs: 60,      // 1 minuto de tolerancia
            max_past_secs: 24 * 3600, // nax 24 horas de antigüedad
        }
    }
}

#[derive(Debug)]
pub struct ValidationReport {
    pub valid: Vec<CheckResult>,
    pub rejected: Vec<RejectedResult>,
}

#[derive(Debug)]
pub struct RejectedResult {
    pub check_id: String,
    pub reason: String,
}

// Valida un lote de resultados enviados por un agente.
//
// Flujo
// * Validar timestamps de todos los resultados (sin bbdd)
// * Recoger los check_ids unicos y validar en bbdd que pertenece al agente.
// * Separar validos de rechazados
//
// Los resultados rechazados se devuelven en `ValidationReport::Rejected`: El ingester los incluye
// en la respuesta al agente sin interrumpir el procesamiento de los validos
pub async fn validate_batch(
    pool: &PgPool,
    agent_id: Uuid,
    results: &[CheckResult],
    bounds: &TimestampBounds,
) -> Result<ValidationReport, IngesterError> {
    if results.is_empty() {
        return Ok(ValidationReport {
            valid: vec![],
            rejected: vec![],
        });
    }

    //    if results.is_empty() {
    //        return Ok(ValidationReport {
    //            valid: vec![],
    //            rejected: vec![],
    //        });
    //    }

    let now = Utc::now();
    let mut valid = Vec::new();
    let mut rejected = Vec::new();
    let mut candidate_check_ids = Vec::new();

    // Validar timestamps
    for result in results {
        if let Some(reason) = validate_timestamp(result.executed_at, &now, bounds) {
            rejected.push(RejectedResult {
                check_id: result.check_id.clone(),
                reason,
            });
            continue;
        }

        // Parsear el check_id como UUID
        match result.check_id.parse::<Uuid>() {
            Ok(id) => {
                candidate_check_ids.push(id);
                valid.push(result.clone());
            }

            Err(_) => {
                rejected.push(RejectedResult {
                    check_id: result.check_id.clone(),
                    reason: format!("check_id '{}' no es un UUID valido", result.check_id),
                });
            }
        }
    }

    if valid.is_empty() {
        return Ok(ValidationReport { valid, rejected });
    }

    // Validar que los check_ids pertenecen al agente en la bbdd
    let invalid_ids =
        db_results::validate_check_ids_for_agent(pool, agent_id, &candidate_check_ids)
            .await
            .map_err(IngesterError::Database)?;

    if !invalid_ids.is_empty() {
        let invalid_set: std::collections::HashSet<String> =
            invalid_ids.iter().map(|id| id.to_string()).collect();

        // Separar los que fallaron la validación de BD
        let (still_valid, newly_rejected): (Vec<_>, Vec<_>) = valid
            .into_iter()
            .partition(|r| !invalid_set.contains(&r.check_id));

        for r in newly_rejected {
            rejected.push(RejectedResult {
                check_id: r.check_id.clone(),
                reason: format!(
                    "check_id '{}' no pertenece a ninguna política asignada a este agente",
                    r.check_id
                ),
            });
        }

        valid = still_valid;

        tracing::warn!(
            agent_id = %agent_id,
            invalid_count = invalid_ids.len(),
            "check_ids rechazados por no pertenecer al agente"
        );
    }

    tracing::debug!(
        agent_id = %agent_id,
        valid = valid.len(),
        rejected = rejected.len(),
        "validación completada"
    );

    Ok(ValidationReport { valid, rejected })
}

// Valida el timestamp de un resultado individual. Devuelve `Some(motivo)` si es invalido, `None`
// si es valido.
fn validate_timestamp(
    executed_at_unix: i64,
    now: &DateTime<Utc>,
    bounds: &TimestampBounds,
) -> Option<String> {
    let executed_at = match DateTime::from_timestamp(executed_at_unix, 0) {
        Some(t) => t,
        None => return Some(format!("timestamp unix invalido: {}", executed_at_unix)),
    };

    let max_future = *now + Duration::seconds(bounds.max_future_secs);

    if executed_at > max_future {
        return Some(format!(
            "timestamp {} es del futuro (maximo tolerado: {} segundos)",
            executed_at.format("%Y-%m-%dTH:%M:%SZ"),
            bounds.max_future_secs,
        ));
    }

    let min_future = *now - Duration::seconds(bounds.max_past_secs);

    if executed_at < min_future {
        return Some(format!(
            "timestamp {} es demasiado antiguo (maximo tolerado: {} segundos)",
            executed_at.format("%Y-%m-%dTH:%M:%SZ"),
            bounds.max_past_secs,
        ));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn bounds() -> TimestampBounds {
        TimestampBounds {
            max_future_secs: 60,
            max_past_secs: 3600,
        }
    }

    #[test]
    fn valid_timestamp_passes() {
        let now = Utc::now();
        let ts = now.timestamp();
        assert!(validate_timestamp(ts, &now, &bounds()).is_none());
    }

    #[test]
    fn future_timestamp_rejected() {
        let now = Utc::now();
        let future = (now + Duration::seconds(120)).timestamp();
        assert!(validate_timestamp(future, &now, &bounds()).is_some());
    }

    #[test]
    fn old_timestamp_rejected() {
        let now = Utc::now();
        let old = (now - Duration::seconds(7200)).timestamp();
        assert!(validate_timestamp(old, &now, &bounds()).is_some());
    }

    #[test]
    fn slightly_future_within_tolerance_passes() {
        let now = Utc::now();
        let slightly_future = (now + Duration::seconds(30)).timestamp();
        assert!(validate_timestamp(slightly_future, &now, &bounds()).is_none());
    }
}
