//! Interceptor gRPC: extrae la identidad del agente del certificado de cliente.
//!
//! En cada request al puerto principal, este interceptor:
//!
//! * Extrae el certificado de cliente del handshake TLS.
//! * Parsea el CN, que es el hostname del agente.
//! * Busca el agente en bbdd por su hostname para obtener su UUID.
//! * Verifica que el certificado no esta revocado.
//! * Inyecta el `AgentId` como `Extension` en el request para que los servicios puedan usarlo sin
//! repetir esta logica.
//!
//! Si cualquier paso falla, la peticion se rechaza con `Status::Unauthenticated`

use tonic::{Request, Status};
use uuid::Uuid;

use db::PgPool;

// Identificador del agente autenticado, inyectado por el interceptor. Se extrae con
// `req.extension().get::<AgentId>()` en los servicios.
#[derive(Clone, Debug)]
pub struct AgentId(pub Uuid);

#[derive(Clone)]
pub struct InterceptorState {
    pub pool: std::sync::Arc<PgPool>,
}

// Interceptor que verifica la identidad del agente en cada request. Se registra en tonic con
// `.layer(InterceptorLayer::New(state)`. Tonic pasa el PEM del certificado de cliente en los
// metadatos bajo la key `x-tls-client-crt` cuando se configura correctamente.
//
// El certificado de cliente esta disponible a traves de las peer credentials del stream gRPC en
// esta version de tonic.

pub async fn auth_interceptor(
    mut req: Request<()>,
    state: InterceptorState,
) -> Result<Request<()>, Status> {
    // Extraer el PEM del certificado de cliente de los metadatos del request. Tonic lo inyecta bajo
    // la clave "x-tls-client-cert" cuando está configurado para pasar las peer credentials.
    let cert_pem = req
        .metadata()
        .get("x-tls-client-cert")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            Status::unauthenticated("certificado de cliente no presente en el request")
        })?;

    // Parsear el certificado para extraer el CN y el serial
    let (cn, serial) = parse_cert_cn_and_serial(cert_pem).map_err(|e| {
        tracing::warn!(error = %e, "certificado de cliente inválido");
        Status::unauthenticated("certificado de cliente inválido")
    })?;

    // Verificar que el certificado no está revocado
    let is_revoked = grpc_pki::is_cert_revoked(&state.pool, &serial)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "error verificando revocación del certificado");
            Status::internal("error verificando el certificado")
        })?;

    if is_revoked {
        tracing::warn!(serial = %serial, cn = %cn, "certificado revocado rechazado");
        return Err(Status::unauthenticated("certificado revocado"));
    }

    // Buscar el agente por su hostname (CN del certificado)
    let agent = db::agents::get_agent_by_hostname(&state.pool, &cn)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, cn = %cn, "error buscando agente");
            Status::internal("error de autenticación")
        })?
        .ok_or_else(|| {
            tracing::warn!(cn = %cn, "agente no encontrado para el CN del certificado");
            Status::unauthenticated("agente no registrado")
        })?;

    // Verificar que el agente está habilitado
    if !agent.enabled {
        tracing::warn!(agent_id = %agent.id, cn = %cn, "agente deshabilitado rechazado");
        return Err(Status::permission_denied("agente deshabilitado"));
    }

    tracing::debug!(
        agent_id = %agent.id,
        cn = %cn,
        "agente autenticado"
    );

    // Inyectar el AgentId en las extensiones del request
    req.extensions_mut().insert(AgentId(agent.id));

    Ok(req)
}

// Parsea el CN y el serial de un certificado en PEM. Devuelve `(cn, serial_hex)`
fn parse_cert_cn_and_serial(cert_pem: &str) -> Result<(String, String), String> {
    let der = pem::parse(cert_pem).map_err(|e| format!("PEM invalido: {}", e))?;

    let (_, cert) = x509_parser::parse_x509_certificate(der.contents())
        .map_err(|e| format!("certificado x509 invalido: {}", e))?;

    // extraer el CN del subject
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .ok_or_else(|| "certificado sin CN en el subject".to_string())?
        .to_string();

    // serial en hex
    let serial = hex::encode(cert.serial.to_bytes_be());

    Ok((cn, serial))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cert_invalid_pem_returns_error() {
        let result = parse_cert_cn_and_serial("not a certificate");
        assert!(result.is_err());
    }
}
