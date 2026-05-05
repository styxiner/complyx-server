//! Resolucion de politicas por agente.
//!
//! Para cada agente, el distribuidor resuelve que `PolicyBundle` debe reibir combinando:
//! * Politicas asignadas directamente al agente
//! * Politicas asignadas a los grupos a los que pertenece el agente
//!
//! El resultado es un `PolicyBundle` proto listo para enviar en `PollResponse`, como su hash
//! SHA-256 calculado para la deteccion de cambios.
//!
//! Deduplicado:
//!
//! Si la misma politica esta asignada directamente y a traves de un grupo, aparece una sola vez en
//! el bundle. La deduplicacion se hace por `policy_id` antes de cargar los detalles, evitando
//! consultas innecesarias.

use std::collections::HashSet;
use std::sync::Arc;

use db::PgPool;
use db::{agents as db_agents, policies as db_policies};
use uuid::Uuid;

use proto::{Policy, PolicyBundle, PolicyCheck, PolicyElement, PolicyRemediation};

use crate::DistributorError;
use crate::hasher;

// Distribuidor de politicas
//
// Barato de clonar porque usa `Arc<PgPool>` internamente
#[derive(Clone)]
pub struct PolicyDistributor {
    pool: Arc<PgPool>,
}

impl PolicyDistributor {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    /// Resuelve el `PolicyBundle` completo para un agente.
    ///
    /// # Flujo
    ///
    /// 1. Obtener IDs de políticas directas del agente.
    /// 2. Obtener IDs de grupos del agente.
    /// 3. Obtener IDs de políticas de esos grupos.
    /// 4. Unión + deduplicación de IDs.
    /// 5. Para cada ID único: cargar el bundle completo de la política.
    /// 6. Construir el `PolicyBundle` proto y calcular su hash.
    ///
    /// Las queries de paso 1, 2 y 3 se hacen en paralelo con `tokio::try_join!`.
    /// Las cargas de bundles individuales (paso 5) también se hacen en paralelo.
    pub async fn resolve_for_agent(
        &self,
        agent_id: Uuid,
    ) -> Result<PolicyBundle, DistributorError> {
        let pool = &*self.pool;

        // Pasos 1, 2 y 3 en paralelo
        let (direct_ids, group_ids) = tokio::try_join!(
            db_policies::get_direct_policies_for_agent(pool, agent_id),
            db_agents::get_agent_group_ids(pool, agent_id),
        )
        .map_err(DistributorError::Database)?;

        let group_policy_ids = if group_ids.is_empty() {
            vec![]
        } else {
            db_policies::get_policies_for_groups(pool, &group_ids)
                .await
                .map_err(DistributorError::Database)?
        };

        // Deduplicar: unión de directas + grupos
        let all_policy_ids: Vec<Uuid> = {
            let mut seen = HashSet::new();
            direct_ids
                .into_iter()
                .chain(group_policy_ids)
                .filter(|id| seen.insert(*id))
                .collect()
        };

        tracing::debug!(
            agent_id = %agent_id,
            policy_count = all_policy_ids.len(),
            "políticas resueltas para agente"
        );

        if all_policy_ids.is_empty() {
            let empty = PolicyBundle {
                bundle_hash: hasher::bundle_hash(&PolicyBundle {
                    bundle_hash: String::new(),
                    policies: vec![],
                }),
                policies: vec![],
            };
            return Ok(empty);
        }

        // Cargar los bundles completos en paralelo
        let bundle_futures: Vec<_> = all_policy_ids
            .iter()
            .map(|&id| db_policies::get_policy_bundle(pool, id))
            .collect();

        let db_bundles = futures::future::try_join_all(bundle_futures)
            .await
            .map_err(DistributorError::Database)?;

        // Construir el PolicyBundle proto
        let policies: Vec<Policy> = db_bundles
            .into_iter()
            .flatten() // quitar los None (política eliminada entre resolve y load)
            .map(db_bundle_to_proto)
            .collect();

        // Calcular hash sobre el bundle sin el campo bundle_hash para evitar recursion. El hash se
        // calcula sobre el contenido, no sobre si mismo.
        let mut bundle = PolicyBundle {
            bundle_hash: String::new(),
            policies,
        };
        bundle.bundle_hash = hasher::bundle_hash(&bundle);

        tracing::info!(
            agent_id = %agent_id,
            policies = bundle.policies.len(),
            bundle_hash = %bundle.bundle_hash,
            "bundle construido"
        );

        Ok(bundle)
    }
}

/// Convierte un `db::policies::PolicyBundle` (filas de BD) al tipo proto `PolicyBundle` que se
/// serializa y envia al agente.
fn db_bundle_to_proto(db_bundle: db_policies::PolicyBundle) -> Policy {
    let db_policies::PolicyBundle {
        policy,
        elements,
        checks,
        remediations,
        check_regulation_sections,
    } = db_bundle;

    // Indexar remediaciones por check_id para acceso O(1)
    let rem_by_check: std::collections::HashMap<Uuid, &db_policies::PolicyRemediationRow> =
        remediations
            .iter()
            .map(|r| (r.policy_check_id, r))
            .collect();

    // Indexar secciones de normativa por check_id
    let sections_by_check: std::collections::HashMap<Uuid, Vec<String>> = check_regulation_sections
        .iter()
        .fold(std::collections::HashMap::new(), |mut acc, s| {
            acc.entry(s.check_id)
                .or_default()
                .push(s.regulation_section_id.to_string());
            acc
        });

    // Indexar checks por policy_element_id
    let checks_by_element: std::collections::HashMap<Uuid, Vec<&db_policies::PolicyCheckRow>> =
        checks
            .iter()
            .fold(std::collections::HashMap::new(), |mut acc, c| {
                acc.entry(c.policy_element_id).or_default().push(c);
                acc
            });

    // Construir los elementos con sus checks
    let proto_elements: Vec<PolicyElement> = elements
        .iter()
        .map(|el| {
            let el_checks = checks_by_element
                .get(&el.id)
                .map(|v| v.as_slice())
                .unwrap_or(&[]);

            let proto_checks: Vec<PolicyCheck> = el_checks
                .iter()
                .map(|c| {
                    let remediation = rem_by_check.get(&c.id).map(|r| PolicyRemediation {
                        id: r.id.to_string(),
                        remediation_type: remediation_type_from_json(&r.remediation_command),
                        remediation_params_json: r.remediation_command.clone(),
                    });

                    let regulation_section_ids =
                        sections_by_check.get(&c.id).cloned().unwrap_or_default();

                    PolicyCheck {
                        id: c.id.to_string(),
                        name: c.name.clone(),
                        check_type: check_type_from_json(&c.check_command),
                        check_params_json: c.check_command.clone(),
                        regulation_section_ids,
                        remediation,
                    }
                })
                .collect();

            PolicyElement {
                id: el.id.to_string(),
                name: el.name.clone().unwrap_or_default(),
                checks: proto_checks,
            }
        })
        .collect();

    Policy {
        id: policy.id.to_string(),
        name: policy.name.clone(),
        version: policy.version.clone(),
        severity: policy.severity.clone().unwrap_or_default(),
        elements: proto_elements,
    }
}

/// Extrae el `type` del JSON de check_command.
///
/// El `check_command` en BD es el JSON completo con `type` y params. El agente espera `check_type`
/// y `check_params_json` separados en el proto. Aqui se extrae el tipo. El json completo va en
/// `check_params_json`
///
/// Si el JSON no tiene campo `type`, devuelve "unknown" para que el agente lo registre como check
/// no soportado en vez de petar.
fn check_type_from_json(json: &str) -> String {
    serde_json::from_str::<serde_json::Value>(json)
        .ok()
        .and_then(|v| v.get("type")?.as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "unknown".to_string())
}

/// Extrae el `type` del JSON de remediation_command.
fn remediation_type_from_json(json: &str) -> String {
    serde_json::from_str::<serde_json::Value>(json)
        .ok()
        .and_then(|v| v.get("type")?.as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_type_from_valid_json() {
        let json = r#"{"type": "file_line", "path": "/etc/login.defs", "key": "PASS_MIN_LEN"}"#;
        assert_eq!(check_type_from_json(json), "file_line");
    }

    #[test]
    fn check_type_from_invalid_json_returns_unknown() {
        assert_eq!(check_type_from_json("not json"), "unknown");
        assert_eq!(check_type_from_json(r#"{"no_type": true}"#), "unknown");
    }

    #[test]
    fn test_remediation_type_from_json() {
        let json = r#"{"type": "file_line_set", "key": "PASS_MIN_LEN", "value": "15"}"#;
        assert_eq!(remediation_type_from_json(json), "file_line_set");
    }
}
