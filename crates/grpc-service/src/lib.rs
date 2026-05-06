//! implementacion de los dos servicios gRPC del servidor Complyx:
//!
//! * `AgentServiceImpl`: servicio principal (puerto 9000, mTLS). Gestiona polls, resultados y
//! heartbeats de los agentes registrados.
//! * `EnrollServiceImpl`: servicio de registro (puerto 9001, TLS unidireccional). Valida tokens y
//! emite certificados a los nuevos agentes.
//!
//! ## Uso previsto para `server-core`
//! ```ignore
//! use grpc_service::{AgentServiceImpl, EnrollServiceImpl};
//! use proto::complyx::complyx_agent_server::ComplyxAgentServer;
//! use proto::complyx::complyx_enroll_server::ComplyxEnrollServer;
//!
//! // Puerto principal con mTLS
//! let agent_server = Server::builder()
//!     .tls_config(mtls_config)?
//!     .add_service(ComplyxAgentServer::with_interceptor(
//!         agent_svc,
//!         move |req| interceptor::auth_interceptor(req, state.clone()),
//!     ))
//!     .serve(addr_9000);
//!
//! // Puerto de enrolamiento sin mTLS
//! let enroll_server = Server::builder()
//!     .tls_config(tls_config)?
//!     .add_service(ComplyxEnrollServer::new(enroll_svc))
//!     .serve(addr_9001);
//!
//! tokio::join!(agent_server, enroll_server);
//! ```

pub mod agent_service;
pub mod enroll_service;
pub mod interceptor;

pub use agent_service::AgentServiceImpl;
pub use enroll_service::EnrollServiceImpl;
pub use interceptor::{AgentId, InterceptorState, auth_interceptor};
