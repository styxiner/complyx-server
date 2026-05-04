//! Pool de conexiones PostgreSQL.

//use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::DbError;

/// Conecta al servidor PostgreSQL y devuelve un pool de conexiones.
///
/// La URL sigue el formato estándar de PostgreSQL:
/// `postgres://usuario:password@host:5432/complyx`
///
/// El pool usa hasta 10 conexiones concurrentes por defecto. Para producción
/// con muchos agentes simultáneos se puede subir con la opción `max_connections`.
pub async fn connect(database_url: &str) -> Result<PgPool, DbError> {
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .min_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .idle_timeout(std::time::Duration::from_secs(600))
        .max_lifetime(std::time::Duration::from_secs(1800))
        .connect(database_url)
        .await
        .map_err(DbError::Pool)?;

    tracing::info!("pool PostgreSQL inicializado");
    Ok(pool)
}

/// Ejecuta todas las migrations pendientes.
///
/// Las migrations viven en `migrations/` en la raíz del workspace del servidor.
/// sqlx mantiene una tabla `_sqlx_migrations` en la BD para rastrear qué
/// migrations se han aplicado. Es idempotente.
pub async fn run_migrations(pool: &PgPool) -> Result<(), DbError> {
    sqlx::migrate!("../../migrations")
        .run(pool)
        .await
        .map_err(|e| DbError::Migration(e.to_string()))?;

    tracing::info!("migrations PostgreSQL aplicadas");
    Ok(())
}
