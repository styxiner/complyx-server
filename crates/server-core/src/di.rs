//! Inyeccion de dependencias
//!
//! `AppState` construye e inicializa todos los componentes del servidor en el orden correcto y los
//! expone como campos publicos para que `main.rs` los pase a los servicios gRPC con el siguiente
//! orden de inicializacion:
//!
//! * Pool PostgreSQL + migrations
//! * CA (carga del disco o generacion si es la primera vez)
//! * Orchestrator + monitor de heartbeats
//! * PolicyDistributor, ResultIngester
//! * Servicios gRPC (AgentServiceImpl y EnrollServiceImpl)
//! * Configuraciones TLS (mTLS y TLS unidireccional)

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use db::PgPool;
use grpc_pki::{build_mtls_config, build_tls_config};
use grpc_service::{AgentServiceImpl, EnrollServiceImpl, InterceptorState, agent_service};
use orchestrator::{Orchestrator, heartbeat};
use pki::CertificateAuthority;
use policy_distributor::PolicyDistributor;
use result_ingester::ResultIngester;
use tonic::transport::ServerTlsConfig;

use crate::config::ServerConfig;

// Estado global del server con los componentes inicializados
pub struct AppState {
    pub pool: Arc<PgPool>,
    pub ca: Arc<CertificateAuthority>,
    pub orchestrator: Orchestrator,
    pub agent_service: AgentServiceImpl,
    pub enroll_service: EnrollServiceImpl,
    pub mtls_config: ServerTlsConfig,
    pub tls_config: ServerTlsConfig,
    pub interceptor_state: InterceptorState,
    pub shutdown_tx: watch::Sender<bool>, // Sender para detener el monitor de heartbeats al apagar
                                          //el servidor
}

impl AppState {
    pub async fn build(config: &ServerConfig) -> anyhow::Result<Self> {
        // Pool de PostgreSQL
        let pool = db::connect(&config.database_url)
            .await
            .map_err(|e| anyhow::anyhow!("no se pudo conectar a PostgreSQL: {}", e))?;

        tracing::info!(database_url = %sanitize_url(&config.database_url), "conectado a PostgreSQL");

        // Aplicar las migraciones
        db::run_migrations(&pool)
            .await
            .map_err(|e| anyhow::anyhow!("error aplicando las migraciones: {}", e))?;

        tracing::info!("migraiones aplicadas");

        let pool = Arc::new(pool);

        // CA interna
        let ca = CertificateAuthority::load_or_create(&config.ca_dir)
            .await
            .map_err(|e| anyhow::anyhow!("error inicializando CA: {}", e))?;

        tracing::info!(
            ca_dir = %config.ca_dir.display(),
            "CA inicializada"
        );

        let ca = Arc::new(ca);

        // Orchestrator y monitor de heartbeats
        let orchestrator = Orchestrator::new(config.agent_offline_timeout_secs);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let check_interval = Duration::from_secs(config.agent_offline_timeout_secs / 2);

        heartbeat::spawn_monitor(orchestrator.clone(), check_interval, shutdown_rx);

        tracing::info!(
            offline_timeout_secs = config.agent_offline_timeout_secs,
            "orchestrator y heartbeat monitor iniciados"
        );

        // Distribuidor de politicas e ingestor de resultados
        let distributor = PolicyDistributor::new(Arc::clone(&pool));
        let ingester = ResultIngester::new(Arc::clone(&pool));

        // Servidor gRPC
        let agent_service = AgentServiceImpl::new(
            Arc::clone(&pool),
            orchestrator.clone(),
            distributor,
            ingester,
        );

        let enroll_service = EnrollServiceImpl::new(
            Arc::clone(&pool),
            Arc::clone(&ca),
            config.cert_validity_days,
        );

        let interceptor_state = InterceptorState {
            pool: Arc::clone(&pool),
        };

        // Configurar TLS
        let mtls_config = build_mtls_config(&config.ca_dir)
            .await
            .map_err(|e| anyhow::anyhow!("error construyendo la configuracion mTLS: {}", e))?;

        let tls_config = build_tls_config(&config.ca_dir)
            .await
            .map_err(|e| anyhow::anyhow!("error construyendo la configuracion TLS: {}", e))?;

        tracing::info!("configuraciones TLS construidas");

        Ok(Self {
            pool,
            ca,
            orchestrator,
            agent_service,
            enroll_service,
            mtls_config,
            tls_config,
            interceptor_state,
            shutdown_tx,
        })
    }

    // Envia la señal de parada a todos los componentes de fondo.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

// elimina la contraseña de la URL de la bbdd para el log (que queda muy gitano si no JAJJAJAJAJA)
fn sanitize_url(url: &str) -> String {
    if let Some(at_pos) = url.find('@') {
        if let Some(colon_pos) = url[..at_pos].rfind(':') {
            let scheme_end = url.find("://").map(|p| p + 3).unwrap_or(0);

            if colon_pos > scheme_end {
                return format!("{}:***{}", &url[..colon_pos], &url[at_pos..]);
            }
        }
    }

    url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_url_hides_password() {
        let url = "postgres://complyx:secreto@localhost/complyx";
        let sanitized = sanitize_url(url);
        assert!(!sanitized.contains("secreto"));
        assert!(sanitized.contains("complyx:***@localhost"));
    }

    #[test]
    fn sanitize_url_without_password_unchanged() {
        let url = "postgres://localhost/complyx";
        assert_eq!(sanitize_url(url), url);
    }
}
