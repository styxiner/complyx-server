//! Inicializacion del sistema de logging estructurado.
//!
//! Soporta estos formatos:
//! * `json`: recomendado para produccion; una linea JSON por evento, compatible con ELK y otros
//! servicios de ingesta de datos.
//! * `pretty`: recomendado para desarrollo; formato legible con colorines en la terminal.
//!
//! El nivel de log se puede sobreescribir con la variable `RUST_LOG`.

use tracing_subscriber::{EnvFilter, fmt};

use crate::config::{LogFormat, ServerConfig};

// Inicializar el sistema de logging. Debe llamarse lo antes posible en `main()`, antes que
// cualquier otra operacin que pueda emitir logs. Solo puede llamarse una vez.
pub fn init(config: &ServerConfig) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    match config.log_format {
        LogFormat::Json => {
            fmt()
                .json()
                .with_env_filter(filter)
                .with_current_span(true)
                .with_span_list(false)
                .with_target(true)
                .init();
        }

        LogFormat::Pretty => {
            fmt()
                .pretty()
                .with_env_filter(filter)
                .with_target(true)
                .init();
        }
    }
}
