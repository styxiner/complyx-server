//! Queries sobre políticas, elementos, checks, remediaciones y sus asignaciones.

//use chrono::{DateTime, Utc, NaiveDateTime};
use chrono::NaiveDateTime;
use sqlx::PgPool;
use uuid::Uuid;

use crate::DbError;


#[derive(Debug, Clone)]
pub struct PolicyRow {
    pub id: Uuid,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub severity: Option<String>,
    pub created_date: NaiveDateTime,
    pub last_modified: NaiveDateTime,
}

#[derive(Debug, Clone)]
pub struct PolicyElementRow {
    pub id: Uuid,
    pub policy_id: Uuid,
    pub name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PolicyCheckRow {
    pub id: Uuid,
    pub policy_element_id: Uuid,
    pub name: String,
    pub rationale: Option<String>,
    pub check_command: String, // JSON con el tipo de check y sus parámetros
    pub created_date: NaiveDateTime,
}

#[derive(Debug, Clone)]
pub struct PolicyRemediationRow {
    pub id: Uuid,
    pub policy_check_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub remediation_command: String, // JSON con el tipo de remediación y sus parámetros
    pub created_date: NaiveDateTime,
}

#[derive(Debug, Clone)]
pub struct CheckRegulationSectionRow {
    pub check_id: Uuid,
    pub regulation_section_id: Uuid,
}


/// Bundle completo de una política: elementos + checks + remediaciones + secciones.
/// Es lo que el `policy-distributor` necesita para construir el `PolicyBundle` proto.
#[derive(Debug)]
pub struct PolicyBundle {
    pub policy: PolicyRow,
    pub elements: Vec<PolicyElementRow>,
    pub checks: Vec<PolicyCheckRow>,
    pub remediations: Vec<PolicyRemediationRow>,
    pub check_regulation_sections: Vec<CheckRegulationSectionRow>,
}

/// Carga el bundle completo de una política en 5 queries paralelas.
///
/// Se hace en queries separadas (no con JOIN) para evitar el producto cartesiano
/// que generaría filas duplicadas cuando hay múltiples elementos × checks × secciones.
pub async fn get_policy_bundle(pool: &PgPool, policy_id: Uuid,) -> Result<Option<PolicyBundle>, DbError> {
    // Cargar la política base
    let policy = match get_policy(pool, policy_id).await? {
        Some(p) => p,
        None => return Ok(None),
    };

    // Las cuatro queries secundarias pueden ir en paralelo
    let (elements, checks, remediations, sections) = tokio::try_join!(
        get_elements_for_policy(pool, policy_id),
        get_checks_for_policy(pool, policy_id),
        get_remediations_for_policy(pool, policy_id),
        get_regulation_sections_for_policy(pool, policy_id),
    )?;

    Ok(Some(PolicyBundle {
        policy,
        elements,
        checks,
        remediations,
        check_regulation_sections: sections,
    }))
}


pub async fn get_policy(pool: &PgPool, id: Uuid) -> Result<Option<PolicyRow>, DbError> {
    sqlx::query_as!(
        PolicyRow,
        r#"
        SELECT id, name, version, description, severity, created_date, last_modified
        FROM policies
        WHERE id = $1
        "#,
        id
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)
}

pub async fn list_policies(pool: &PgPool) -> Result<Vec<PolicyRow>, DbError> {
    sqlx::query_as!(
        PolicyRow,
        "SELECT id, name, version, description, severity, created_date, last_modified \
         FROM policies ORDER BY name"
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)
}


/// Políticas asignadas directamente a un agente.
pub async fn get_direct_policies_for_agent(pool: &PgPool, agent_id: Uuid,) -> Result<Vec<Uuid>, DbError> {
    let rows = sqlx::query!(
        "SELECT policy_id FROM agent_policies WHERE agent_id = $1",
        agent_id
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;

    Ok(rows.into_iter().map(|r| r.policy_id).collect())
}

/// Políticas asignadas a uno o varios grupos.
///
/// Recibe una slice de group_ids porque un agente puede pertenecer a varios grupos.
/// Devuelve IDs deduplicados.
pub async fn get_policies_for_groups(pool: &PgPool, group_ids: &[Uuid],) -> Result<Vec<Uuid>, DbError> {
    if group_ids.is_empty() {
        return Ok(vec![]);
    }

    let rows = sqlx::query!(
        r#"
        SELECT DISTINCT policy_id
        FROM group_policies
        WHERE group_id = ANY($1)
        "#,
        group_ids
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;

    Ok(rows.into_iter().map(|r| r.policy_id).collect())
}

/// Asigna una política a un agente directamente.
pub async fn assign_policy_to_agent(pool: &PgPool, agent_id: Uuid, policy_id: Uuid,) -> Result<(), DbError> {
    sqlx::query!(
        r#"
        INSERT INTO agent_policies (agent_id, policy_id)
        VALUES ($1, $2)
        ON CONFLICT DO NOTHING
        "#,
        agent_id,
        policy_id,
    )
    .execute(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(())
}

/// Asigna una política a un grupo.
pub async fn assign_policy_to_group(pool: &PgPool, group_id: Uuid, policy_id: Uuid,) -> Result<(), DbError> {
    sqlx::query!(
        r#"
        INSERT INTO group_policies (group_id, policy_id)
        VALUES ($1, $2)
        ON CONFLICT DO NOTHING
        "#,
        group_id,
        policy_id,
    )
    .execute(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(())
}

/// Desasigna una política de un agente.
pub async fn unassign_policy_from_agent(pool: &PgPool, agent_id: Uuid, policy_id: Uuid,) -> Result<(), DbError> {
    sqlx::query!(
        "DELETE FROM agent_policies WHERE agent_id = $1 AND policy_id = $2",
        agent_id,
        policy_id
    )
    .execute(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(())
}

async fn get_elements_for_policy(pool: &PgPool, policy_id: Uuid,) -> Result<Vec<PolicyElementRow>, DbError> {
    sqlx::query_as!(
        PolicyElementRow,
        "SELECT id, policy_id, name FROM policy_elements WHERE policy_id = $1 ORDER BY id",
        policy_id
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)
}

async fn get_checks_for_policy(pool: &PgPool, policy_id: Uuid,) -> Result<Vec<PolicyCheckRow>, DbError> {
    sqlx::query_as!(
        PolicyCheckRow,
        r#"
        SELECT pc.id, pc.policy_element_id, pc.name, pc.rationale,
               pc.check_command, pc.created_date
        FROM policy_checks pc
        INNER JOIN policy_elements pe ON pc.policy_element_id = pe.id
        WHERE pe.policy_id = $1
        ORDER BY pe.id, pc.id
        "#,
        policy_id
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)
}

async fn get_remediations_for_policy(pool: &PgPool, policy_id: Uuid,) -> Result<Vec<PolicyRemediationRow>, DbError> {
    sqlx::query_as!(
        PolicyRemediationRow,
        r#"
        SELECT pr.id, pr.policy_check_id, pr.name, pr.description,
               pr.remediation_command, pr.created_date
        FROM policy_remediations pr
        INNER JOIN policy_checks pc ON pr.policy_check_id = pc.id
        INNER JOIN policy_elements pe ON pc.policy_element_id = pe.id
        WHERE pe.policy_id = $1
        ORDER BY pc.id, pr.id
        "#,
        policy_id
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)
}

async fn get_regulation_sections_for_policy(pool: &PgPool, policy_id: Uuid,) -> Result<Vec<CheckRegulationSectionRow>, DbError> {
    sqlx::query_as!(
        CheckRegulationSectionRow,
        r#"
        SELECT crs.check_id, crs.regulation_section_id
        FROM check_regulation_sections crs
        INNER JOIN policy_checks pc ON crs.check_id = pc.id
        INNER JOIN policy_elements pe ON pc.policy_element_id = pe.id
        WHERE pe.policy_id = $1
        "#,
        policy_id
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)
}
