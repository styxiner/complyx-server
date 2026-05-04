//! Queries para persistir resultados de checks enviados por los agentes.

//use chrono::{DateTime, Utc, NaiveDateTime, TimeZone};
use chrono::{Utc, NaiveDateTime, TimeZone};
use sqlx::PgPool;
use uuid::Uuid;

use crate::DbError;

/// Resultado de un check tal como se almacena en la BD.
#[derive(Debug, Clone)]
pub struct CheckResultRow {
    pub id: Uuid,
    pub agent_id: Uuid,
    pub check_id: Uuid,
    pub passed: bool,
    pub detail: String,
    pub actual_value: Option<String>,
    pub expected_value: Option<String>,
    pub executed_at: NaiveDateTime,
    pub received_at: NaiveDateTime,
}

/// Score de cumplimiento de un elemento de política para un agente.
#[derive(Debug, Clone)]
pub struct ComplianceScoreRow {
    pub agent_id: Uuid,
    pub policy_element_id: Uuid,
    pub policy_id: Uuid,
    pub total_checks: i64,
    pub passed_checks: i64,
    /// Porcentaje de cumplimiento (0.0 - 100.0)
    pub score: f64,
    pub last_updated: NaiveDateTime,
}

/// Datos de un resultado recibido del agente para insertar en la BD.
#[derive(Debug, Clone)]
pub struct InsertCheckResult {
    pub agent_id: Uuid,
    pub check_id: Uuid,
    pub passed: bool,
    pub detail: String,
    pub actual_value: String,
    pub expected_value: String,
    /// Timestamp Unix (segundos) tal como lo envía el agente
    pub executed_at_unix: i64,
}

/// Inserta un lote de resultados de checks en una sola transacción.
///
/// Usa `INSERT ... ON CONFLICT DO NOTHING` para que sea idempotente:
/// si el agente reenvía resultados que ya estaban en la BD (por un flush
/// duplicado), no genera errores ni duplicados.
pub async fn insert_check_results(pool: &PgPool, results: &[InsertCheckResult],) -> Result<usize, DbError> {
    if results.is_empty() {
        return Ok(0);
    }

    let mut tx = pool.begin().await.map_err(DbError::Query)?;
    let mut inserted = 0usize;

    for r in results {
        // Convertir timestamp Unix a NaiveDateTime
//        let executed_at = DateTime::from_timestamp(r.executed_at_unix, 0)
//            .unwrap_or_else(Utc::now);
        let executed_at: NaiveDateTime = Utc
            //.timestamp_opt(r.executed_at_unix, 0)
            .timestamp_opt(r.executed_at_unix, 0)
            .single()
            .unwrap_or_else(|| Utc::now())
            .naive_utc();

        let result = sqlx::query!(
            r#"
            INSERT INTO check_results
                (agent_id, check_id, passed, detail, actual_value, expected_value, executed_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (agent_id, check_id, executed_at) DO NOTHING
            "#,
            r.agent_id,
            r.check_id,
            r.passed,
            r.detail,
            r.actual_value,
            r.expected_value,
            executed_at,
        )
            .execute(&mut *tx)
            .await
            .map_err(DbError::Query)?;

        inserted += result.rows_affected() as usize;
    }

    tx.commit().await.map_err(DbError::Query)?;

    tracing::debug!(
        agent_id = %results[0].agent_id,
        inserted,
        total = results.len(),
        "resultados de checks insertados"
    );

    Ok(inserted)
}

/// Recalcula y persiste el score de cumplimiento de todos los elementos
/// de política para un agente, basándose en los resultados más recientes.
///
/// Un "resultado más reciente" es el último `passed`/`failed` para cada `check_id`.
/// Se usa un UPSERT para que llamadas repetidas actualicen en lugar de duplicar.
pub async fn upsert_compliance_scores(pool: &PgPool, agent_id: Uuid,) -> Result<Vec<ComplianceScoreRow>, DbError> {
    // Calcula los scores en una sola query usando window functions
    let scores = sqlx::query_as!(
        ComplianceScoreRow,
        r#"
        WITH latest_results AS (
            -- Para cada check del agente, tomar solo el resultado más reciente
            SELECT DISTINCT ON (check_id)
                check_id,
                passed
            FROM check_results
            WHERE agent_id = $1
            ORDER BY check_id, executed_at DESC
        ),
        element_scores AS (
            SELECT
                pe.id          AS policy_element_id,
                pe.policy_id,
                COUNT(pc.id)   AS total_checks,
                COUNT(lr.check_id) FILTER (WHERE lr.passed = true) AS passed_checks
            FROM policy_elements pe
            INNER JOIN policy_checks pc ON pc.policy_element_id = pe.id
            LEFT JOIN latest_results lr ON lr.check_id = pc.id
            GROUP BY pe.id, pe.policy_id
        )
        INSERT INTO compliance_scores
            (agent_id, policy_element_id, policy_id, total_checks, passed_checks, score, last_updated)
        SELECT
            $1 AS agent_id,
            policy_element_id,
            policy_id,
            total_checks,
            passed_checks,
            CASE WHEN total_checks > 0
                THEN (passed_checks::float / total_checks::float) * 100.0
                ELSE 0.0
            END AS score,
            now() AS last_updated
        FROM element_scores
        ON CONFLICT (agent_id, policy_element_id) DO UPDATE SET
            total_checks  = EXCLUDED.total_checks,
            passed_checks = EXCLUDED.passed_checks,
            score         = EXCLUDED.score,
            last_updated  = EXCLUDED.last_updated
        RETURNING
            agent_id,
            policy_element_id,
            policy_id,
            total_checks,
            passed_checks,
            score,
            last_updated
        "#,
        agent_id
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;

    Ok(scores)
}

/// Devuelve los resultados más recientes de un agente para todos sus checks.
pub async fn get_latest_results_for_agent(pool: &PgPool, agent_id: Uuid,) -> Result<Vec<CheckResultRow>, DbError> {
    sqlx::query_as!(
        CheckResultRow,
        r#"
        SELECT DISTINCT ON (check_id)
            id, agent_id, check_id, passed, detail,
            actual_value, expected_value, executed_at, received_at
        FROM check_results
        WHERE agent_id = $1
        ORDER BY check_id, executed_at DESC
        "#,
        agent_id
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)
}

/// Verifica que todos los `check_id` de un lote de resultados existen en la BD
/// y están asignados (a través de su política) al agente que los envía.
///
/// Devuelve los IDs que NO son válidos para ese agente.
/// Se usa en el `validator` del `result-ingester`.
pub async fn validate_check_ids_for_agent(pool: &PgPool, agent_id: Uuid, check_ids: &[Uuid],) -> Result<Vec<Uuid>, DbError> {
    if check_ids.is_empty() {
        return Ok(vec![]);
    }

    // Check IDs válidos = checks que pertenecen a políticas asignadas al agente
    // (directamente o por grupo)
    let valid = sqlx::query!(
        r#"
        SELECT DISTINCT pc.id AS check_id
        FROM policy_checks pc
        INNER JOIN policy_elements pe ON pc.policy_element_id = pe.id
        WHERE pc.id = ANY($1)
          AND (
              -- Asignación directa
              EXISTS (
                  SELECT 1 FROM agent_policies ap
                  WHERE ap.agent_id = $2 AND ap.policy_id = pe.policy_id
              )
              OR
              -- Asignación por grupo
              EXISTS (
                  SELECT 1 FROM group_policies gp
                  INNER JOIN agent_group_membership agm ON gp.group_id = agm.group_id
                  WHERE agm.agent_id = $2 AND gp.policy_id = pe.policy_id
              )
          )
        "#,
        check_ids,
        agent_id,
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;

    let valid_ids: std::collections::HashSet<Uuid> = valid.into_iter().map(|r| r.check_id).collect();

    let invalid: Vec<Uuid> = check_ids
        .iter()
        .filter(|id| !valid_ids.contains(id))
        .copied()
        .collect();

    Ok(invalid)
}
