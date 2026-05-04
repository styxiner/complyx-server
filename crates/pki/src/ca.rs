//! Autoridad Certificadora interna de Complyx.
//!
//! La CA raíz se genera la primera vez que arranca el servidor y se persiste
//! en `ca_dir` (por defecto `/var/lib/complyx/pki/`). En arranques posteriores
//! se carga del disco.
//!
//! ## Ficheros en disco
//!
//! ```text
//! /var/lib/complyx/pki/
//!   ca.crt   — certificado raíz (público, se distribuye a los agentes)
//!   ca.key   — clave privada (0600, nunca sale del servidor)
//! ```
//!
//! ## Seguridad de la clave privada
//!
//! La clave privada de la CA nunca se almacena en la base de datos.
//! Reside únicamente en el sistema de ficheros con permisos 0600.
//! En producción debería residir en un volumen cifrado o HSM.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rcgen::{BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,};
use tokio::sync::RwLock;

use x509_parser::prelude::FromDer;

use crate::PkiError;

const CA_VALIDITY_YEARS: i64 = 10;

// Autoridad Certificadora interna.
//
// Es `Clone` y barato de clonar: internamente usa `Arc` para compartir la CA entre el servicio de
// registro y el builder de TLS
#[derive(Clone)]
pub struct CertificateAuthority {
    inner: Arc<CaInner>,
}

struct CaInner {
    cert: RwLock<rcgen::Certificate>, // Certificado raíz en memoria (rcgen lo necesita para firmar CSRs)
    ca_cert_pem: String, // PEM del certificado raíz (se envía a los agentes en el enrolamiento)
    ca_dir: PathBuf, // Directorio donde se persiste la CA
}

impl CertificateAuthority {
    // Carga la CA del disco si existe, o la genera y la persiste si es la primera vez.
    //
    // # Errores
    //
    // * `PkiError::Io` si no se puede leer o escribir el directorio.
    // * `PkiError::CertGeneration` si falla la generación o parseo de la CA.
    pub async fn load_or_create(ca_dir: impl AsRef<Path>) -> Result<Self, PkiError> {
        let ca_dir = ca_dir.as_ref().to_path_buf();
        let cert_path = ca_dir.join("ca.crt");
        let key_path  = ca_dir.join("ca.key");

        if cert_path.exists() && key_path.exists() {
            tracing::info!(ca_dir = %ca_dir.display(), "cargando CA existente del disco");
            Self::load_from_disk(&cert_path, &key_path, ca_dir).await
        } else {
            tracing::info!(ca_dir = %ca_dir.display(), "generando nueva CA raíz");
            Self::generate_and_persist(ca_dir).await
        }
    }

    // Firma un CSR recibido de un agente y devuelve el certificado en PEM.
    //
    // # Argumentos
    //
    // * `csr_pem` — CSR del agente en formato PEM.
    // * `hostname` — hostname del agente, se usa como CN en el certificado emitido.
    // * `validity_days` — duración del certificado en días.
    //
    // # Devuelve
    //
    // Tupla `(cert_pem, serial_hex)`:
    // * `cert_pem` — certificado firmado en PEM para guardar en disco en el agente.
    // * `serial_hex` — número de serie en hex para almacenar en `agent_certs`.
    pub async fn sign_csr(&self, csr_pem: &str, hostname: &str, validity_days: i64,) -> Result<(String, String), PkiError> {
        // Parsear el CSR con x509-parser para validarlo antes de firmarlo
        let csr_der = pem_to_der(csr_pem, "CERTIFICATE REQUEST")?;
        let (_, csr) = x509_parser::certification_request::X509CertificationRequest::from_der(&csr_der)
            .map_err(|e| PkiError::CsrParse(e.to_string()))?;

        // Verificar la firma del CSR (el agente posee la clave privada correspondiente)
        csr.verify_signature()
            .map_err(|e| PkiError::CsrSignatureInvalid(e.to_string()))?;

        // Construir los parámetros del certificado a emitir
        let mut params = CertificateParams::default();

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, hostname);
        dn.push(DnType::OrganizationName, "Complyx Agent");
        params.distinguished_name = dn;

        // Validez: desde ahora hasta validity_days días en el futuro
        let now = rcgen::date_time_ymd(
            chrono::Utc::now().year() as i32,
            chrono::Utc::now().month() as u8,
            chrono::Utc::now().day() as u8,
        );
        let expiry_date = chrono::Utc::now() + chrono::Duration::days(validity_days);
        let expiry = rcgen::date_time_ymd(
            expiry_date.year() as i32,
            expiry_date.month() as u8,
            expiry_date.day() as u8,
        );
        params.not_before = now;
        params.not_after  = expiry;

        // El certificado de agente NO es CA
        params.is_ca = IsCa::NoCa;

        // Uso: autenticación de cliente TLS
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature,];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth,];

        // Número de serie aleatorio
        let serial = generate_serial();
        params.serial_number = Some(rcgen::SerialNumber::from_slice(&hex::decode(&serial)
            .map_err(|e| PkiError::CertGeneration(e.to_string()))?));

        // Extraer la clave pública del CSR para incluirla en el certificado
        let public_key_der = csr.certification_request_info.subject_pki.raw;
        let key_pair = KeyPair::from_der(public_key_der)
            .map_err(|e| PkiError::CertGeneration(e.to_string()))?;
        params.key_pair = Some(key_pair);

        // Firmar con la CA
        let ca = self.inner.cert.read().await;
        let cert = Certificate::from_params(params)
            .map_err(|e| PkiError::CertGeneration(e.to_string()))?;
        let cert_pem = cert.serialize_pem_with_signer(&ca)
            .map_err(|e| PkiError::CertGeneration(e.to_string()))?;

        tracing::info!(
            hostname,
            serial = %serial,
            validity_days,
            "certificado emitido para agente"
        );

        Ok((cert_pem, serial))
    }

    // PEM del certificado raíz de la CA. Se envia a los agentes durante el registro para que
    // puedan verificar el certificado del servidor en el mTLS.
    pub fn ca_cert_pem(&self) -> &str {
        &self.inner.ca_cert_pem
    }

    // Construye la configuración TLS del servidor para Tonic. Incluye el certificado raiz para
    // verificar los certificados de cliente (mTLS)
    pub fn server_tls_config(&self) -> Result<tonic::transport::ServerTlsConfig, PkiError> {
        // Para construir el ServerTlsConfig necesitamos también el certificado y clave del
        // servidor (distinto de la CA). En este diseño la CA firma tambien el certificado del
        // servidor, pero este se carga desde `ca_dir`
        todo!("implementado en grpc-pki que tiene acceso al cert del servidor")
    }
}

impl CertificateAuthority {
    async fn generate_and_persist(ca_dir: PathBuf) -> Result<Self, PkiError> {
        tokio::fs::create_dir_all(&ca_dir)
            .await
            .map_err(|e| PkiError::Io { path: ca_dir.display().to_string(), source: e })?;

        // Generar keypair ECDSA P-256
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| PkiError::CertGeneration(e.to_string()))?;

        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Complyx Internal CA");
        dn.push(DnType::OrganizationName, "Complyx");
        params.distinguished_name = dn;

        // Válido 10 años
        let now   = chrono::Utc::now();
        let expiry = now + chrono::Duration::days(CA_VALIDITY_YEARS * 365);
        params.not_before = rcgen::date_time_ymd(
            now.year() as i32, now.month() as u8, now.day() as u8,
        );
        params.not_after = rcgen::date_time_ymd(
            expiry.year() as i32, expiry.month() as u8, expiry.day() as u8,
        );

        // Es CA: puede firmar otros certificados
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        params.key_pair = Some(key_pair);

        let cert = Certificate::from_params(params)
            .map_err(|e| PkiError::CertGeneration(e.to_string()))?;

        let cert_pem = cert.serialize_pem()
            .map_err(|e| PkiError::CertGeneration(e.to_string()))?;
        let key_pem = cert.serialize_private_key_pem();

        // Persistir en disco
        let cert_path = ca_dir.join("ca.crt");
        let key_path  = ca_dir.join("ca.key");

        tokio::fs::write(&cert_path, cert_pem.as_bytes())
            .await
            .map_err(|e| PkiError::Io { path: cert_path.display().to_string(), source: e })?;

        tokio::fs::write(&key_path, key_pem.as_bytes())
            .await
            .map_err(|e| PkiError::Io { path: key_path.display().to_string(), source: e })?;

        // Permisos 0600 en la clave privada
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                .await
                .map_err(|e| PkiError::Io { path: key_path.display().to_string(), source: e })?;
        }

        tracing::info!(
            cert = %cert_path.display(),
            key  = %key_path.display(),
            "CA raíz generada y persistida"
        );

        let ca_cert_pem = cert_pem.clone();
        Ok(Self {
            inner: Arc::new(CaInner {
                cert: RwLock::new(cert),
                ca_cert_pem,
                ca_dir,
            }),
        })
    }

    async fn load_from_disk(cert_path: &Path, key_path: &Path, ca_dir: PathBuf,) -> Result<Self, PkiError> {
        let cert_pem = tokio::fs::read_to_string(cert_path)
            .await
            .map_err(|e| PkiError::Io { path: cert_path.display().to_string(), source: e })?;

        let key_pem = tokio::fs::read_to_string(key_path)
            .await
            .map_err(|e| PkiError::Io { path: key_path.display().to_string(), source: e })?;

        let key_pair = KeyPair::from_pem(&key_pem)
            .map_err(|e| PkiError::CertGeneration(e.to_string()))?;

        let params = CertificateParams::from_ca_cert_pem(&cert_pem, key_pair)
            .map_err(|e| PkiError::CertGeneration(e.to_string()))?;

        let cert = Certificate::from_params(params)
            .map_err(|e| PkiError::CertGeneration(e.to_string()))?;

        Ok(Self {
            inner: Arc::new(CaInner {
                cert: RwLock::new(cert),
                ca_cert_pem: cert_pem,
                ca_dir,
            }),
        })
    }
}

/// Convierte un PEM a DER extrayendo el bloque con el label dado.
fn pem_to_der(pem: &str, expected_label: &str) -> Result<Vec<u8>, PkiError> {
    let parsed = pem::parse(pem)
        .map_err(|e| PkiError::CsrParse(e.to_string()))?;

    if parsed.tag() != expected_label {
        return Err(PkiError::CsrParse(format!(
            "se esperaba '{}' pero se encontró '{}'",
            expected_label,
            parsed.tag()
        )));
    }

    Ok(parsed.into_contents())
}

/// Genera un número de serie de 16 bytes aleatorio en hex.
fn generate_serial() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Combinamos timestamp + bytes de UUID para tener unicidad sin rand
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let id = uuid::Uuid::new_v4();
    format!("{:016x}{}", ts & 0xFFFF_FFFF_FFFF_FFFF, hex::encode(id.as_bytes()))
}

// Helpers de chrono para rcgen (rcgen usa su propio tipo de fecha)
trait ChronoExt {
    fn year(&self) -> i32;
    fn month(&self) -> u8;
    fn day(&self) -> u8;
}

impl ChronoExt for chrono::DateTime<chrono::Utc> {
    fn year(&self) -> i32 { 
        chrono::Datelike::year(self) 
    }
    
    fn month(&self) -> u8 { 
        chrono::Datelike::month(self) as u8 
    }
    
    fn day(&self) -> u8 { 
        chrono::Datelike::day(self) as u8 
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn generates_ca_and_persists_to_disk() {
        let dir = tempdir().unwrap();
        let ca = CertificateAuthority::load_or_create(dir.path()).await.unwrap();

        assert!(!ca.ca_cert_pem().is_empty());
        assert!(ca.ca_cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(dir.path().join("ca.crt").exists());
        assert!(dir.path().join("ca.key").exists());
    }

    #[tokio::test]
    async fn loads_existing_ca_from_disk() {
        let dir = tempdir().unwrap();

        // Primera carga: genera
        let ca1 = CertificateAuthority::load_or_create(dir.path()).await.unwrap();
        let pem1 = ca1.ca_cert_pem().to_string();

        // Segunda carga: debe cargar la misma CA
        let ca2 = CertificateAuthority::load_or_create(dir.path()).await.unwrap();
        assert_eq!(pem1, ca2.ca_cert_pem(), "debe cargar el mismo certificado");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ca_key_has_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        CertificateAuthority::load_or_create(dir.path()).await.unwrap();

        let meta = std::fs::metadata(dir.path().join("ca.key")).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "ca.key debe tener permisos 0o600");
    }

    #[test]
    fn generate_serial_is_unique() {
        let s1 = generate_serial();
        let s2 = generate_serial();
        // Muy improbable que colisionen dos UUIDs
        assert_ne!(s1, s2);
        // Deben ser hex válido
        assert!(s1.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
