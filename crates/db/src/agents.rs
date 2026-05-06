//! Queries sobre los agentes, grupos y sus relaciones.

//use chrono::{DateTime, Utc, NaiveDateTime};
use chrono::NaiveDateTime;
use sqlx::PgPool;
use sqlx::types::ipnetwork::IpNetwork;
use uuid::Uuid;

use crate::DbError;

// Rows: tipos que mapean directamente a filas de la bbdd

#[derive(Debug, Clone)]
pub struct AgentRow {
    pub id: Uuid,
    pub ip: String,
    pub hostname: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    //    pub install_date: DateTime<Utc>,
    pub install_date: NaiveDateTime,
    //    pub latest_connection: DateTime<Utc>,
    pub latest_connection: NaiveDateTime,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct AgentGroupRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    //    pub created_date: DateTime<Utc>,
    pub created_date: NaiveDateTime,
}

#[derive(Debug, Clone)]
pub struct UpsertAgentData {
    pub ip: IpNetwork,
    pub hostname: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
}

// Seccion de agentes

// Obtiene un agente por su UUID. Devuelve `None` si no existe
pub async fn get_agent(pool: &PgPool, id: Uuid) -> Result<Option<AgentRow>, DbError> {
    sqlx::query_as!(
        AgentRow,
        r#"
        SELECT id, ip::text AS "ip!", hostname, os_name, os_version, install_date, latest_connection, enabled
        FROM agents
        WHERE id = $1
        "#,
        id
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)
}

// No me gusta esto, por si existe algun "fallo" de que en una red existen 2 maquinas con el mismo
// hostname, pero bueno. De por si sería raro.
pub async fn get_agent_by_hostname(
    pool: &PgPool,
    hostname: &str,
) -> Result<Option<AgentRow>, DbError> {
    sqlx::query_as!(
        AgentRow,
        r#"
        SELECT id, ip::text AS "ip!", hostname, os_name, os_version, install_date, latest_connection, enabled
        FROM agents
        WHERE hostname = $1
        LIMIT 1
        "#,
        hostname
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)
}

// Inserta un agente nuevo o actualiza sus datos si ya existe (basandose en la IP)
//
// Se usa en el registro: Si un agente con la misma IP ya existe, se actualiza en vez de crear un
// duplicado. Devuelve el UUID del agente insertado o actualizado.
pub async fn upsert_agent(pool: &PgPool, data: &UpsertAgentData) -> Result<Uuid, DbError> {
    let row = sqlx::query!(
        r#"
        INSERT INTO agents (ip, hostname, os_name, os_version, latest_connection)
        VALUES ($1::inet, $2, $3, $4, now())
        ON CONFLICT (ip) DO UPDATE SET 
            hostname = EXCLUDED.hostname,
            os_name = EXCLUDED.os_name,
            os_version = EXCLUDED.os_version,
            latest_connection = now()
        RETURNING id
        "#,
        data.ip,
        data.hostname,
        data.os_name,
        data.os_version,
    )
    .fetch_one(pool)
    .await
    .map_err(DbError::Query)?;

    Ok(row.id)
}

// Actualiza el timestamp `last_connection` de un agente. Se llama en cada heartbeat y en cada
// poll.
pub async fn update_latest_connection(pool: &PgPool, agent_id: Uuid) -> Result<(), DbError> {
    sqlx::query!(
        r#"
        UPDATE agents 
        SET latest_connection = now()
        WHERE id = $1
        "#,
        agent_id
    )
    .execute(pool)
    .await
    .map_err(DbError::Query)?;

    Ok(())
}

// Habilita o deshabilita un agente
pub async fn set_enabled(pool: &PgPool, agent_id: Uuid, enabled: bool) -> Result<(), DbError> {
    sqlx::query!(
        r#"
        UPDATE agents 
        SET enabled = $1
        WHERE id = $2
        "#,
        enabled,
        agent_id
    )
    .execute(pool)
    .await
    .map_err(DbError::Query)?;

    Ok(())
}

pub async fn delete_agent(pool: &PgPool, agent_id: Uuid) -> Result<(), DbError> {
    sqlx::query!(
        r#"
        DELETE
        FROM agents
        WHERE id = $1
        "#,
        agent_id
    )
    .execute(pool)
    .await
    .map_err(DbError::Query)?;

    Ok(())
}

pub async fn list_agents(pool: &PgPool) -> Result<Vec<AgentRow>, DbError> {
    sqlx::query_as!(
        AgentRow,
        r#"
        SELECT id, ip::text AS "ip!", hostname, os_name, os_version, install_date, latest_connection, enabled
        FROM agents 
        ORDER BY hostname, id 
        "#
    )
        .fetch_all(pool)
        .await
    .map_err(DbError::Query)
}

// Grupos de los agentes

pub async fn get_agent_groups(
    pool: &PgPool,
    agent_id: Uuid,
) -> Result<Vec<AgentGroupRow>, DbError> {
    sqlx::query_as!(
        AgentGroupRow,
        r#"
        SELECT ag.id, ag.name, ag.description, ag.created_date
        FROM agent_groups ag
        INNER JOIN agent_group_membership agm ON ag.id = agm.group_id
        WHERE agm.agent_id = $1
        ORDER BY ag.name 
        "#,
        agent_id
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)
}

pub async fn get_agent_group_ids(pool: &PgPool, agent_id: Uuid) -> Result<Vec<Uuid>, DbError> {
    let rows = sqlx::query!(
        r#"
        SELECT group_id
        FROM agent_group_membership
        WHERE agent_id = $1
        "#,
        agent_id
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;

    Ok(rows.into_iter().map(|r| r.group_id).collect())
}

pub async fn add_agent_to_group(
    pool: &PgPool,
    agent_id: Uuid,
    group_id: Uuid,
) -> Result<(), DbError> {
    sqlx::query!(
        r#"
        INSERT INTO agent_group_membership (agent_id, group_id)
        VALUES ($1, $2)
        ON CONFLICT DO NOTHING
        "#,
        agent_id,
        group_id
    )
    .execute(pool)
    .await
    .map_err(DbError::Query)?;

    Ok(())
}

pub async fn remove_agent_from_group(
    pool: &PgPool,
    agent_id: Uuid,
    group_id: Uuid,
) -> Result<(), DbError> {
    sqlx::query!(
        r#"
        DELETE 
        FROM agent_group_membership
        WHERE agent_id = $1 AND group_id = $2
        "#,
        agent_id,
        group_id
    )
    .execute(pool)
    .await
    .map_err(DbError::Query)?;

    Ok(())
}

pub async fn get_group(pool: &PgPool, id: Uuid) -> Result<Option<AgentGroupRow>, DbError> {
    sqlx::query_as!(
        AgentGroupRow,
        r#"
        SELECT id, name, description, created_date
        FROM agent_groups
        WHERE id = $1
        "#,
        id
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)
}

pub async fn list_groups(pool: &PgPool) -> Result<Vec<AgentGroupRow>, DbError> {
    sqlx::query_as!(
        AgentGroupRow,
        "SELECT id, name, description, created_date FROM agent_groups ORDER BY name"
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)
}
