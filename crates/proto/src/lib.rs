//! Crate de tipos generados a partir de `complyx.proto`
//!
//! Expone todos los mensajes Protobuf y los stubs de cliente gRPC bajo el modulo `complyx`. El
//! codigo real esta generado por `tonic-build` en compilacion y esta en `$OUT_DIR/complyx.rs`.
//!
//!
//! Los tipos generados aqui son el contrato (descripción del protocolo) de red entre agente y servidor .
//! Los crates de lógica de negocio (`policy-engine`, `remediation-engine`, `result-ingester`...)
//! **no deben depender de este crate directamente**: trabajan con sus propios tipos de dominio.
//! Solo `grpc-client` (en el agente) y `grpc-service` (en el servidor) importan este crate y hacen
//! la conversion entre tipos proto y tipos de dominio.


//! Modulo que contiene todos los tipos generados a partir de `complyx.proto`.
//!
//! El nombre del modulo coincide con el `package complyx;` declarado en el proto.

pub mod complyx {
    // tonic-build escribe el codigo generado en $OUT_DIR/complyx.rs durante compilación. Este
    // include! lo incorpora al crate en compilacion
    tonic::include_proto!("complyx");
}

// Permite importar los tipos mas usados directamente desde `proto::` en lugar de tener que
// escribir `proto::complyx::` en cada import. Solo re-exportará los tipos que los crates
// consumidos necesitan con frecuencia
pub use complyx::{
    CheckResult,
    EnrollRequest,
    EnrollResponse,
    HeartbeatRequest,
    HeartbeatResponse,
    Policy,
    PolicyBundle,
    PolicyCheck,
    PolicyElement,
    PolicyRemediation,
    PollRequest,
    PollResponse,
    SubmitResultsRequest,
    SubmitResultsResponse,
};

// Metodos de conveniencia sobre los tipos generados que se me olvidaron implementar cuando lo subi

impl PolicyBundle {
    pub fn total_checks(&self) -> usize {
        self.policies
            .iter()
            .flat_map(|p| &p.elements)
            .flat_map(|e| &e.checks)
            .count()

    }
}

impl PolicyRemediation {
    // `true` si este mensaje tiene una remediacioon reeal configurada. En el proto3 los campos
    // opcionales se inicializan a string vacio, asi que un `id` vacio significa "sin remediacion"
    pub fn is_configured(&self) -> bool {
        !self.id.is_empty()
    }
}

impl CheckResult {
    // Construye un CheckResult de error (passed = false)
    pub fn execution_error(check_id: impl Into<String>, detail: impl Into<String>) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        Self {
            check_id: check_id.into(),
            passed: false,
            detail: detail.into(),
            actual_value: String::new(),
            expected_value: String::new(),
            executed_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,

        }
    }

    // Construye un CheckResult para tipo de check no soportado
    pub fn unsupported_type(check_id: impl Into<String>, check_type: &str) -> Self {
        Self::execution_error(
            check_id,
            format!("tipo de check '{}' no soportado", check_type),
            )
    }
}
