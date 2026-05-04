//! Queries sobre amenazas y riesgos.

use bigdecimal::BigDecimal;
//use chrono::{DateTime, Utc, NaiveDateTime};
use chrono::{Utc, NaiveDateTime};
use sqlx::PgPool;
use uuid::Uuid;

use crate::DbError;


#[derive(Debug, Clone)]
pub struct ThreatRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub category: Option<String>,
    pub severity_score: Option<f64>,
    pub created_date: NaiveDateTime,
}

#[derive(Debug, Clone)]
pub struct RiskRow {
    pub id: Uuid,
    pub threat_id: Uuid,
    pub agent_id: Uuid,
    pub impact: Option<f64>,
    pub probability: Option<f64>,
    pub risk_level: Option<String>,
    pub status: String,
    pub created_date: NaiveDateTime,
    pub review_date: Option<NaiveDateTime>,
    pub acceptance_date: Option<NaiveDateTime>,
}

/// Datos para crear un riesgo nuevo (usado por el `risk_trigger` del `result-ingester`).
#[derive(Debug, Clone)]
pub struct InsertRiskData {
    pub threat_id: Uuid,
    pub agent_id: Uuid,
    pub impact: Option<f64>,
    pub probability: Option<f64>,
    pub risk_level: Option<String>,
}


pub async fn get_threat(pool: &PgPool, id: Uuid) -> Result<Option<ThreatRow>, DbError> {
    sqlx::query_as!(
        ThreatRow,
        r#"
        SELECT id, name, description, category,
               severity_score::float8 AS severity_score,
               created_date
        FROM threats WHERE id = $1
        "#,
        id
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)
}

pub async fn list_threats(pool: &PgPool) -> Result<Vec<ThreatRow>, DbError> {
    sqlx::query_as!(
        ThreatRow,
        r#"
        SELECT id, name, description, category,
               severity_score::float8 AS severity_score,
               created_date
        FROM threats ORDER BY name
        "#
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)
}


/// Obtiene un riesgo por su UUID.
pub async fn get_risk(pool: &PgPool, id: Uuid) -> Result<Option<RiskRow>, DbError> {
    sqlx::query_as!(
        RiskRow,
        r#"
        SELECT id, threat_id, agent_id,
               impact::float8 AS impact,
               probability::float8 AS probability,
               risk_level, status, created_date, review_date, acceptance_date
        FROM risks WHERE id = $1
        "#,
        id
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)
}

/// Lista riesgos abiertos de un agente.
pub async fn list_open_risks_for_agent(pool: &PgPool, agent_id: Uuid,) -> Result<Vec<RiskRow>, DbError> {
    sqlx::query_as!(
        RiskRow,
        r#"
        SELECT id, threat_id, agent_id,
               impact::float8 AS impact,
               probability::float8 AS probability,
               risk_level, status, created_date, review_date, acceptance_date
        FROM risks
        WHERE agent_id = $1 AND status = 'open'
        ORDER BY created_date DESC
        "#,
        agent_id
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)
}

/// Crea un riesgo nuevo. Se usa desde `risk_trigger` cuando un check crítico falla.
pub async fn insert_risk(pool: &PgPool, data: &InsertRiskData) -> Result<Uuid, DbError> {

    // Apaño convirtiendo el valor a BigDecimal antes del bind:
    let impact = data.impact.map(|v| BigDecimal::try_from(v).expect("invalid impact"));
    let probability = data.probability.map(|v| BigDecimal::try_from(v).expect("invalid impact"));

    let row = sqlx::query!(
        r#"
        INSERT INTO risks (threat_id, agent_id, impact, probability, risk_level, status)
        VALUES ($1, $2, $3, $4, $5, 'open')
        RETURNING id
        "#,
        data.threat_id,
        data.agent_id,
        //data.impact,
        //data.probability,
        impact,
        probability,
        data.risk_level,
    )
    .fetch_one(pool)
    .await
    .map_err(DbError::Query)?;

    tracing::info!(
        risk_id = %row.id,
        agent_id = %data.agent_id,
        threat_id = %data.threat_id,
        risk_level = ?data.risk_level,
        "riesgo creado"
    );

    Ok(row.id)
}

/// Comprueba si ya existe un riesgo abierto para un agente y una amenaza concreta.
/// Se usa en `risk_trigger` para no crear duplicados.
pub async fn find_open_risk(pool: &PgPool, agent_id: Uuid, threat_id: Uuid,) -> Result<Option<Uuid>, DbError> {
    let row = sqlx::query!(
        r#"
        SELECT id FROM risks
        WHERE agent_id = $1 AND threat_id = $2 AND status = 'open'
        LIMIT 1
        "#,
        agent_id,
        threat_id,
    )
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)?;

    Ok(row.map(|r| r.id))
}

/// Actualiza el estado de un riesgo.
pub async fn set_risk_status(pool: &PgPool, risk_id: Uuid, status: &str,) -> Result<(), DbError> {
    let acceptance_date = if status == "accepted" {
        Some(Utc::now().naive_utc())
    } else {
        None
    };

    sqlx::query!(
        r#"
        UPDATE risks
        SET status          = $1,
            acceptance_date = COALESCE($2, acceptance_date)
        WHERE id = $3
        "#,
        status,
        acceptance_date,
        risk_id,
    )
    .execute(pool)
    .await
    .map_err(DbError::Query)?;

    Ok(())
}

/// Vincula una política mitigadora a un riesgo.
pub async fn link_policy_to_risk(pool: &PgPool, risk_id: Uuid, policy_id: Uuid,) -> Result<(), DbError> {
    sqlx::query!(
        r#"
        INSERT INTO risk_policies (risk_id, policy_id)
        VALUES ($1, $2)
        ON CONFLICT DO NOTHING
        "#,
        risk_id,
        policy_id,
    )
    .execute(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(())
}
