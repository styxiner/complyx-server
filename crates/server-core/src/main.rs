//! Punto de entrada del servidor
//!
//! Subcomandos por consola
//!
//!```bash
//! complyx-server: arranca el servidor
//! complyx-server enroll-token [--hostname H] [--expiry-hours N]
//! complyx-server revoke-agent --agent-id UUID
//!```

mod config;
mod di;
mod telemetry;

use std::env;

use tonic::transport::Server;

use proto::complyx::complyx_agent_server::ComplyxAgentServer;
use proto::complyx::complyx_enroll_server::ComplyxEnrollServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parsear argumentos antes de inicializar el loggin porque los comandos de terminal no
    // necesitan el servidor completo.
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("enroll-token") => return cmd_enroll_token(&args).await,
        Some("revoke-token") => return cmd_revoke_agent(&args).await,
        Some("--help") | Some("-h") => {
            print_usage();
            return Ok(());
        }

        _ => {} // continua con el arranque del servidor
    }

    // configuracion
    let config = config::load(None)?;

    // telemetria antes de cualquier log
    telemetry::init(&config);

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        grpc_port = config.grpc_port,
        enroll_port = config.enroll_port,
        ca_dir = %config.ca_dir.display(),
        "complyx-server arrancando"
    );

    // Inyeccion de dependencias: inicializa la bbdd, ca, servicios gRPC y TLS...
    let state = di::AppState::build(&config).await?;

    tracing::info!("todos los componentes inicializados");

    // Arrancar los dos servidores gRPC en paralelo
    let grpc_addr = config.grpc_addr();
    let enroll_addr = config.enroll_addr();

    tracing::info!(
        addr = %grpc_addr,
        "servidor gRPC principal (mTLS) arrancando"
    );

    tracing::info!(
        addr = %enroll_addr,
        "servidor de registro (TLS) arrancando"
    );

    let interceptor_state = state.interceptor_state.clone();
    let agent_svc = state.agent_service.clone();
    let enroll_svc = state.enroll_service.clone();
    let mtls_config = state.mtls_config.clone();
    let tls_config = state.tls_config.clone();

    // Servidor principal: mTLS + interceptor de autenticación
    let agent_server = Server::builder()
        .tls_config(mtls_config)?
        .add_service(ComplyxAgentServer::with_interceptor(
            agent_svc,
            move |req| {
                let state = interceptor_state.clone();
                // Tonic interceptors son síncronos, pero necesitamos async para la verificacion de
                // revocacion. Se resuelve en un bloque tokio::task::block_in_place para no
                // bloquear la ejecucion
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(grpc_service::auth_interceptor(req, state))
                })
            },
        ))
        .serve_with_shutdown(grpc_addr, shutdown_signal());

    // Servidor de enrolamiento: TLS one-way, sin interceptor
    let enroll_server = Server::builder()
        .tls_config(tls_config)?
        .add_service(ComplyxEnrollServer::new(enroll_svc))
        .serve_with_shutdown(enroll_addr, shutdown_signal());

    // Ejecutar ambos servidores concurrentemente
    let (r1, r2) = tokio::join!(agent_server, enroll_server);
    r1.map_err(|e| anyhow::anyhow!("servidor gRPC principal falló: {}", e))?;
    r2.map_err(|e| anyhow::anyhow!("servidor de enrolamiento falló: {}", e))?;

    // 5. Shutdown limpio
    state.shutdown();
    tracing::info!("complyx-server finalizado");
    Ok(())
}

// comandos de terminal
async fn cmd_enroll_token(args: &[String]) -> anyhow::Result<()> {
    let config = config::load(None)?;
    telemetry::init(&config);

    let hostname = flag_value(args, "--hostname");
    let expiry_hours: i64 = flag_value(args, "--expiry-hours")
        .and_then(|v| v.parse().ok())
        .unwrap_or(config.enroll_token_expiry_hours);

    let pool = db::connect(&config.database_url)
        .await
        .map_err(|e| anyhow::anyhow!("no se pudo conectar a PostgreSQL: {}", e))?;

    let token = pki::token::generate(&pool, hostname.as_deref(), expiry_hours)
        .await
        .map_err(|e| anyhow::anyhow!("error generando el token: {}", e))?;

    let expires_fmt = token.expires_at.format("%Y-%m-%d %H:%M:%S UTC");

    println!();
    println!("token de registro generado");
    println!();

    if let Some(h) = &token.hostname_hint {
        println!(" Hostname: {}", h);
    }

    println!(" Expira: {}", expires_fmt);
    print!(" Token: {}", token.token);
    println!();

    println!("Usalo en el agente con:");
    println!(
        " COMPLYX_ENROLL_TOKEN={} systemctl start complyx-agent",
        token.token
    );
    println!();

    Ok(())
}

async fn cmd_revoke_agent(args: &[String]) -> anyhow::Result<()> {
    let config = config::load(None)?;
    telemetry::init(&config);

    let agent_id_str =
        flag_value(args, "--agent-id").ok_or_else(|| anyhow::anyhow!("--agent-id requerido"))?;

    let agent_id = agent_id_str
        .parse::<uuid::Uuid>()
        .map_err(|_| anyhow::anyhow!("--agent-id debe ser un UUID valido"))?;

    let pool = db::connect(&config.database_url)
        .await
        .map_err(|e| anyhow::anyhow!("no se puede conectar a PostgreSQL: {}", e))?;

    pki::revoke::revoke_agent_cert(&pool, agent_id)
        .await
        .map_err(|e| anyhow::anyhow!("error revocando certificado: {}", e))?;

    println!("certificado del agente {} revocado correctamente", agent_id);
    println!("el agente recibira Unauthenticated en su proximo poll");

    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal;

    #[cfg(unix)]
    {
        use signal::unix::{SignalKind, signal};

        let mut sigterm = signal(SignalKind::terminate()).expect("no se pudo registrar SIGTERM");

        let mut sigint = signal(SignalKind::interrupt()).expect("no se pudo registrar SIGINT");

        tokio::select! {
            _ = sigterm.recv() => tracing::info!("SIGTERM recibido"),
            _ = sigint.recv() => tracing::info!("SIGINT recibido")
        }
    }

    #[cfg(unix)]
    {
        signal::ctrl_c().await.expect("no se pudo registrar Ctrl+C");
    }
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
}

fn print_usage() {
    println!("complyx-server {}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("USAGE:");
    println!(" complyx-server                           Arrancar el servidor");
    println!(" complyx-server enroll-token              Generar token de enrolamiento");
    println!("  [--hostname <hostname>]");
    println!("  [--expiry-hours <horas>]");
    println!(" complyx-server revoke-agent              Revocar certificado de un agente");
    println!("  --agent-id <uuid>");
    println!();
    println!("CONFIGURACIÓN:");
    println!(" /etc/complyx/server.toml (o COMPLYX_CONFIG_PATH)");
    println!(" Variables de entorno: COMPLYX_DATABASE_URL, COMPLYX_GRPC_PORT, ...");
}
