//! Trigger automatico de riesgos
//!
//! Cuando un check critico o de alta severidad falla, el trigger busca si ya existe un riesgo
//! abierto asociado a ese check. Si no existe, crea uno nuevo. Cuando un check que antes fallaba
//! vuelve a pasar, cierra automaticamente el riesgo asociado.
//!
//! Asociacion check con amenaza
//!
//! La asociacion entre un `check_id` y una `threat_id` se establece a traves del
//! `policy_element` -> `policy` -> severidad. No hay una tabla directa check_amenaza en el esquema
//! planteado (tampoco es como que me vaya a dar mucho tiempo a replantearlo todo con lo que queda).
//!
//! En esta implementacion simplificada (que ya vale para esto), cuando un check critico falla se
//! busca una amenaza generica de la categoria "compliance" para asociarla al riesgo. En una
//! implementacion completa, el administrador configuraria la asociacion check_amenaza en la base de
//! datos.
//!
//! En un futuro, me gustaría usar un enfoque hibrido entre clasificacion supervisada y ranking en
//! el que tenga reglas simples de severidad, categoria, etc... con un modelo que prediga el
//! threat_id dado un text con su contexto (un modelo tipo BERT o algo con XGBosst con features
//! podria funcionar) juntandolo con un ranking en el que dado un check, rankea amenazas candidatas
//! usando learning to rank o fine tuning cross encoder. Siempre añadiendo feedback humano o de
//! foros de threat intelligence o una fuente de confianza revisada.
//!
//! Usar un LLM creo q sería muy costoso por el volumen. Pero habría que estudiarlo más.

use std::sync::Arc;

use uuid::Uuid;

use db::PgPool;
use db::risks as db_risks;

use proto::CheckResult;

use crate::IngesterError;

const CRITICAL_SEVERITIES: &[&str] = &["critical", "high"];

#[derive(Clone)]
pub struct RiskTrigger {
    pool: Arc<PgPool>,
}

impl RiskTrigger {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    // Evalua los resultados recibidos y gestiona los riesgos asociados.
    //
    // Para cada resultado fallido con severidad critical/high:
    // * Si no hay riesgo abierto para (agente, amenaza): crea uno.
    //
    // Para cada resultado que ahora pasa y tenia riesgo abierto:
    // * Cierra el riesgo automaticamente.
    //
    // Argumentos
    // * `check_id`: agente cuyos resultados se estan procesando.
    // * `results`: resultados ya validados del lote.
    // * `check_severities`: mapa de check_id y la severidad para saber cuales son criticos. Si esta
    // vacio, no se crean riesgos.
    pub async fn evaluate(
        &self,
        agent_id: Uuid,
        results: &[CheckResult],
        check_severities: &std::collections::HashMap<String, String>,
    ) -> Result<RiskTriggerSummary, IngesterError> {
        let mut created = 0usize;
        let mut closed = 0usize;

        for result in results {
            let severity = check_severities
                .get(&result.check_id)
                .map(|s| s.as_str())
                .unwrap_or("low");

            if !result.passed && is_critical(severity) {
                if self
                    .maybe_create_risk(agent_id, &result.check_id, severity)
                    .await?
                {
                    created += 1;
                }
            } else if result.passed {
                if self.maybe_close_risk(agent_id, &result.check_id).await? {
                    closed += 1;
                }
            }
        }

        if created > 0 || closed > 0 {
            tracing::info!(
                agent_id = %agent_id,
                risks_created = created,
                risks_closed = closed,
                "riesgos gestionados automaticamente"
            );
        }

        Ok(RiskTriggerSummary { created, closed })
    }

    // Crea un riesgo si no existe ya uno abierto para este agente y check.
    // Devuelve `true` si se creo un riesgo nuevo.
    async fn maybe_create_risk(
        &self,
        agent_id: Uuid,
        check_id: &str,
        severity: &str,
    ) -> Result<bool, IngesterError> {
        // Buscar una amenaza de tipo "compliance" en la bbdd para asociar el riesgo. Si no hay
        // amenazas configuradas, no creamos riesgos.
        let threats = db_risks::list_threats(&self.pool)
            .await
            .map_err(IngesterError::Database)?;

        let threat = match find_compliance_threat(&threats, severity) {
            Some(t) => t,
            None => {
                tracing::debug!(
                    check_id,
                    severity,
                    "no hay amenazas de tipo 'compliance' configurada, omitiendo creacion del riesto"
                );

                return Ok(false);
            }
        };

        // verificar si hay un riesgo para ese agente y amenaza.
        let existing = db_risks::find_open_risk(&self.pool, agent_id, threat.id)
            .await
            .map_err(IngesterError::Database)?;

        if existing.is_some() {
            return Ok(false); // como ya existe, no se debe duplicar
        }

        // calcular el impacto y probabilidad basados en la severidad.
        let (impact, probability, risk_level) = severity_to_risk_params(severity);

        db_risks::insert_risk(
            &self.pool,
            &db::risks::InsertRiskData {
                threat_id: threat.id,
                agent_id,
                impact: Some(impact),
                probability: Some(probability),
                risk_level: Some(risk_level.to_string()),
            },
        )
        .await
        .map_err(IngesterError::Database)?;

        tracing::warn!(
            agent_id = %agent_id,
            check_id,
            severity,
            threat = %threat.name,
            risk_level,
            "riesgo creado automaticamente por check fallido"
        );

        Ok(true)
    }

    async fn maybe_close_risk(
        &self,
        agent_id: Uuid,
        check_id: &str,
    ) -> Result<bool, IngesterError> {
        // Buscar amenazas de tipo compliance
        let threats = db_risks::list_threats(&self.pool)
            .await
            .map_err(IngesterError::Database)?;

        for threat in &threats {
            if !is_compliance_threat(threat) {
                continue;
            }

            if let Some(risk_id) = db_risks::find_open_risk(&self.pool, agent_id, threat.id)
                .await
                .map_err(IngesterError::Database)?
            {
                db_risks::set_risk_status(&self.pool, risk_id, "closed")
                    .await
                    .map_err(IngesterError::Database)?;

                tracing::info!(
                    agent_id = %agent_id,
                    check_id,
                    risk_id = %risk_id,
                    "riesgo cerrado automaticamente por check que ahora pasa"
                );

                return Ok(true);
            }
        }

        Ok(false)
    }
}

#[derive(Debug, Default)]
pub struct RiskTriggerSummary {
    pub created: usize,
    pub closed: usize,
}

fn is_critical(severity: &str) -> bool {
    CRITICAL_SEVERITIES.contains(&severity)
}

// busca una amenaza de categoria 'compliance' apropiada para la severidad dada.
fn find_compliance_threat<'a>(
    threats: &'a [db::risks::ThreatRow],
    severity: &str,
) -> Option<&'a db::risks::ThreatRow> {
    // tiene com oprioridad amenazas con la misma sveridad, luego cualquier compliance
    threats
        .iter()
        .filter(|t| is_compliance_threat(t))
        .find(|t| {
            t.severity_score
                .map(|s| severity_score_matches(s, severity))
                .unwrap_or(false)
        })
        .or_else(|| threats.iter().find(|t| is_compliance_threat(t)))
}

fn is_compliance_threat(threat: &db::risks::ThreatRow) -> bool {
    threat
        .category
        .as_deref()
        .map(|c| c.to_lowercase().contains("compliance"))
        .unwrap_or(false)
}

fn severity_score_matches(score: f64, severity: &str) -> bool {
    match severity {
        "critical" => score >= 9.0,
        "high" => score >= 7.0 && score < 9.0,
        "medium" => score >= 4.0 && score < 7.0,
        _ => score < 4.0, // Los low los cubre implicitamente
    }
}

// convierte la severidad de un check en parametros de riesgo.
fn severity_to_risk_params(severity: &str) -> (f64, f64, &'static str) {
    // (impacto, probabilidad, risk_level)
    match severity {
        "critical" => (9.0, 8.0, "critical"),
        "high" => (7.0, 7.0, "high"),
        _ => (5.0, 5.0, "medium"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_critical_returns_true_for_critical_and_high() {
        assert!(is_critical("critical"));
        assert!(is_critical("high"));
        assert!(!is_critical("medium"));
        assert!(!is_critical("low"));
    }

    #[test]
    fn severity_to_risk_params_returns_correct_levels() {
        let (_, _, level) = severity_to_risk_params("critical");
        assert_eq!(level, "critical");

        let (_, _, level) = severity_to_risk_params("high");
        assert_eq!(level, "high");

        let (_, _, level) = severity_to_risk_params("medium");
        assert_eq!(level, "medium");
    }
}
