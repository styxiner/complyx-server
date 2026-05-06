//! Configuracion del servidor de complyx
//!
//! Capas de configuracion por orden de precedencia:
//! * Variables de entorno `COMPLYX_`
//! * Fichero TOML de configuracion (`/etc/complyx/server.toml` o `COMPLYX_CONFIG_PATH`)
//! * Valores por defecto compilados

use std::path::PathBuf;

use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};
use serde::{Deserialize, Serialize};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/complyx/server.toml";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub database_url: String,

    #[serde(default = "default_grpc_port")]
    pub grpc_port: u16,

    #[serde(default = "default_enroll_port")]
    pub enroll_port: u16,

    #[serde(default = "default_ca_dir")]
    pub ca_dir: PathBuf,

    #[serde(default = "default_cert_validity_days")]
    pub cert_validity_days: i64,

    #[serde(default = "default_enroll_token_expiry_hours")]
    pub enroll_token_expiry_hours: i64,

    #[serde(default = "default_agent_offline_timeout_secs")]
    pub agent_offline_timeout_secs: u64,

    #[serde(default = "default_log_level")]
    pub log_level: String,

    #[serde(default = "default_log_format")]
    pub log_format: LogFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Pretty,
    Json,
}

fn default_grpc_port() -> u16 {
    9000
}

fn default_enroll_port() -> u16 {
    9001
}

fn default_ca_dir() -> PathBuf {
    PathBuf::from("/var/lib/complyx/pki")
}

fn default_cert_validity_days() -> i64 {
    365
}

fn default_enroll_token_expiry_hours() -> i64 {
    24
}

fn default_agent_offline_timeout_secs() -> u64 {
    300
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> LogFormat {
    LogFormat::Json
}

pub fn load(config_path: Option<&str>) -> anyhow::Result<ServerConfig> {
    let path = std::env::var("COMPLYX_CONFIG_PATH")
        .unwrap_or_else(|_| config_path.unwrap_or(DEFAULT_CONFIG_PATH).to_string());

    let config: ServerConfig = Figment::new()
        .merge(Serialized::defaults(ServerConfig::defaults()))
        .merge(Toml::file(&path))
        .merge(Env::prefixed("COMPLYX_").split("__"))
        .extract()
        .map_err(|e| anyhow::anyhow!("error cargando configuracion desde '{}': {}", path, e))?;

    config.validate()?;
    Ok(config)
}

impl ServerConfig {
    fn defaults() -> Self {
        Self {
            database_url: String::new(),
            grpc_port: default_grpc_port(),
            enroll_port: default_enroll_port(),
            ca_dir: default_ca_dir(),
            cert_validity_days: default_cert_validity_days(),
            enroll_token_expiry_hours: default_enroll_token_expiry_hours(),
            agent_offline_timeout_secs: default_agent_offline_timeout_secs(),
            log_level: default_log_level(),
            log_format: default_log_format(),
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.database_url.is_empty() {
            anyhow::bail!(
                "database_udl no configurado. Establecelo en {} o con COMPLYX_DATABASE_URL",
                DEFAULT_CONFIG_PATH
            );
        }

        if self.grpc_port == self.enroll_port {
            anyhow::bail!(
                "grpc_port y enroll_port no pueden ser el mismo puerto ({})",
                self.grpc_port
            );
        }

        Ok(())
    }

    pub fn grpc_addr(&self) -> std::net::SocketAddr {
        format!("0.0.0.0:{}", self.grpc_port)
            .parse()
            .expect("grpc_port invalido")
    }

    pub fn enroll_addr(&self) -> std::net::SocketAddr {
        format!("0.0.0.0:{}", self.enroll_port)
            .parse()
            .expect("enroll_port invalido")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_fails_without_database_url() {
        let cfg = ServerConfig::defaults();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_fails_with_same_ports() {
        let mut cfg = ServerConfig::defaults();
        cfg.database_url = "postgres://test".into();
        cfg.grpc_port = 9000;
        cfg.enroll_port = 9000;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_passes_with_valid_config() {
        let mut cfg = ServerConfig::defaults();
        cfg.database_url = "postgres://complyx:complyx@localhost/complyx".into();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn grpc_addr_parses_correctly() {
        let mut cfg = ServerConfig::defaults();
        cfg.database_url = "postgres://test".into();
        let addr = cfg.grpc_addr();
        assert_eq!(addr.port(), 9000);
    }
}
