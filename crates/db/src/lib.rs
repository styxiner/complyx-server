//! db
//! 
//! Capa de acceso a PostgreSQL del servidor Complyx
//!
//! Toda interaccion con la bbdd pasa por este crate. Los crates de logica de negocio
//! (orchestrator, policy-distributor..) no importan `sqlx` directamente, si no que usan las
//! funciones tipadas que expone este crate.
//!
//! Modulos
//!
//! | Modulo | Tabla que gestiona |
//! |--|--|
//! | `agents` | `agents`, `agent_groups`, `agent_group_membership` |
//! | `policies` | policies, policy_elements, policy_checks, policy_remediations, agent_policies,
//! group_policies, check_regulation_sections |
//! | `results` | `check_results`, `compliance_scores` |
//! | `risks` | `threats`, `risks`, `risk_policies` |
//! | `certs` | `agent_certs`, `enroll_tokens` |
//! 
//! ## Uso
//!
//! ```no_run
//! use db::{connect, run_migrations};
//! //! #[tokio::main]
//! async fn main() -> Result<(), db::DbError> {
//!     let pool = connect("postgres://complyx:complyx@localhost/complyx").await?;
//!     run_migrations(&pool).await?;
//!     Ok(())
//! }
//! ```

mod pool;
pub mod agents;
pub mod certs;
pub mod policies;
pub mod results;
pub mod risks;

pub use pool::{connect, run_migrations};

// Re exportar el pool directamente para que los crates consumidores no necesiten importar sqlx
pub use sqlx::PgPool;

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("error de poll PostgreSQL: {0}")]
    Pool(#[from] sqlx::Error),

    #[error("error de Query: {0}")]
    Query(sqlx::Error),

    #[error("error de la migracion: {0}")]
    Migration(String),

    #[error("recurso no encontrado: {0}")]
    NotFound(String),
}



