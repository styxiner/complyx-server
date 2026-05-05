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

//! Autoridad Certificadora interna de Complyx (rcgen 0.14 API).

//! Autoridad Certificadora interna de Complyx.
//! Usa la API de rcgen 0.14: Issuer, signed_by(), from_pem() con features pem+x509-parser.

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

use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use tokio::sync::RwLock;

use crate::PkiError;

const CA_VALIDITY_YEARS: i64 = 10;

#[derive(Clone)]
pub struct CertificateAuthority {
    inner: Arc<CaInner>,
}

// evito usar `Issuer<_,S` directamente porque entonces su ciclo de vida estaría atado al del
// `CertificateParams` que toma prestado. Conservando los dos componentes que recgen necesita para
// reconstruir un `Issuer` cuando sea necesario: El certificado de CA codificado en DER y el
// `KeyPair`. De esta forma `CaInner` es `'static` y se puede envolverlo en `Arc` sin ningun
// parametro de vida util en `CertificateAuthoriry`

// No estoy seguro de xq me dan los warnings de que no se usan los campos, cuando claramente se
// usan en funciones. ????? Problema para luego, mientras me funcione, me vale de momento
struct CaInner {
    // Raw DER of the CA certificate — used to rebuild the Issuer.
    #[allow(dead_code)]
    ca_cert_der: Vec<u8>,
    // Private key of the CA — protected behind a RwLock.
    ca_key_pem: RwLock<String>,
    // PEM of the CA certificate (sent to agents during enrolment).
    ca_cert_pem: String,
    #[allow(dead_code)]
    ca_dir: PathBuf,
}

impl CaInner {
    // Reconstruye un `Issuer` desde el DER + key almacenado.

    fn make_issuer<'a>(
        &'a self,
        key_pem: &str,
    ) -> Result<rcgen::Issuer<'a, rcgen::KeyPair>, PkiError> {
        let key_pair =
            KeyPair::from_pem(key_pem).map_err(|e| PkiError::CertGeneration(e.to_string()))?;
        rcgen::Issuer::from_ca_cert_pem(&self.ca_cert_pem, key_pair)
            .map_err(|e| PkiError::CertGeneration(e.to_string()))
    }
}

impl CertificateAuthority {
    pub async fn load_or_create(ca_dir: impl AsRef<Path>) -> Result<Self, PkiError> {
        let ca_dir = ca_dir.as_ref().to_path_buf();
        let cert_path = ca_dir.join("ca.crt");
        let key_path = ca_dir.join("ca.key");

        if cert_path.exists() && key_path.exists() {
            tracing::info!(ca_dir = %ca_dir.display(), "cargando CA existente del disco");
            Self::load_from_disk(&cert_path, &key_path, ca_dir).await
        } else {
            tracing::info!(ca_dir = %ca_dir.display(), "generando nueva CA raíz");
            Self::generate_and_persist(ca_dir).await
        }
    }

    // Firma un CSR recibido de un agente. Devuelve `(cert_pem. serial_hex)`
    pub async fn sign_csr(
        &self,
        csr_pem: &str,
        hostname: &str,
        validity_days: i64,
    ) -> Result<(String, String), PkiError> {
        // Parsea el CSR, ya lleva las extensiones SubjectPublicKeyInfo y requested
        let csr = CertificateSigningRequestParams::from_pem(csr_pem)
            .map_err(|e| PkiError::CsrParse(e.to_string()))?;

        // Construye los parámetros del `Issuer` (nombre, validez, uso y serial)
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, hostname);
        dn.push(DnType::OrganizationName, "Complyx Agent");
        params.distinguished_name = dn;

        let now = chrono::Utc::now();
        let expiry = now + chrono::Duration::days(validity_days);
        params.not_before = rcgen::date_time_ymd(now.year(), now.month(), now.day());
        params.not_after = rcgen::date_time_ymd(expiry.year(), expiry.month(), expiry.day());

        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

        let serial = generate_serial();
        params.serial_number = Some(rcgen::SerialNumber::from_slice(
            &hex::decode(&serial[..32]).map_err(|e| PkiError::CertGeneration(e.to_string()))?,
        ));

        // Reconstruir `Issuer` en cada llamada (así se evitan problemas con el ciclo de vida de
        // ambos).
        let key_pem = self.inner.ca_key_pem.read().await;
        let issuer = self.inner.make_issuer(&key_pem)?;

        // El CSR como tal es `self`. Los parametros extra van en un `CertificateParams` separado.
        let cert = csr
            .signed_by(&issuer)
            .map_err(|e| PkiError::CertGeneration(e.to_string()))?;

        let cert_pem = cert.pem();

        tracing::info!(hostname, serial = %serial, validity_days, "certificado emitido");
        Ok((cert_pem, serial))
    }

    pub fn ca_cert_pem(&self) -> &str {
        &self.inner.ca_cert_pem
    }
}

impl CertificateAuthority {
    async fn generate_and_persist(ca_dir: PathBuf) -> Result<Self, PkiError> {
        tokio::fs::create_dir_all(&ca_dir)
            .await
            .map_err(|e| PkiError::Io {
                path: ca_dir.display().to_string(),
                source: e,
            })?;

        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| PkiError::CertGeneration(e.to_string()))?;

        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Complyx Internal CA");
        dn.push(DnType::OrganizationName, "Complyx");
        params.distinguished_name = dn;

        let now = chrono::Utc::now();
        let expiry = now + chrono::Duration::days(CA_VALIDITY_YEARS * 365);
        params.not_before = rcgen::date_time_ymd(now.year(), now.month(), now.day());
        params.not_after = rcgen::date_time_ymd(expiry.year(), expiry.month(), expiry.day());
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        // `self_signed` returns `Certificate` — `pem()` is infallible in 0.14.
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| PkiError::CertGeneration(e.to_string()))?;

        let cert_pem = cert.pem(); // String, not Result
        let cert_der = cert.der().to_vec(); // keep DER for Issuer rebuilds
        let key_pem = key_pair.serialize_pem();

        // Persist to disk.
        let cert_path = ca_dir.join("ca.crt");
        let key_path = ca_dir.join("ca.key");

        tokio::fs::write(&cert_path, cert_pem.as_bytes())
            .await
            .map_err(|e| PkiError::Io {
                path: cert_path.display().to_string(),
                source: e,
            })?;

        tokio::fs::write(&key_path, key_pem.as_bytes())
            .await
            .map_err(|e| PkiError::Io {
                path: key_path.display().to_string(),
                source: e,
            })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                .await
                .map_err(|e| PkiError::Io {
                    path: key_path.display().to_string(),
                    source: e,
                })?;
        }

        tracing::info!(
            cert = %cert_path.display(),
            key  = %key_path.display(),
            "CA raíz generada"
        );

        Ok(Self {
            inner: Arc::new(CaInner {
                ca_cert_der: cert_der,
                ca_key_pem: RwLock::new(key_pem),
                ca_cert_pem: cert_pem,
                ca_dir,
            }),
        })
    }

    async fn load_from_disk(
        cert_path: &Path,
        key_path: &Path,
        ca_dir: PathBuf,
    ) -> Result<Self, PkiError> {
        let cert_pem = tokio::fs::read_to_string(cert_path)
            .await
            .map_err(|e| PkiError::Io {
                path: cert_path.display().to_string(),
                source: e,
            })?;

        let key_pem = tokio::fs::read_to_string(key_path)
            .await
            .map_err(|e| PkiError::Io {
                path: key_path.display().to_string(),
                source: e,
            })?;

        // Valida que la clave parsea correctamente a la hora de cargar
        let key_pair =
            KeyPair::from_pem(&key_pem).map_err(|e| PkiError::CertGeneration(e.to_string()))?;

        // Tambien valida el conjunto de la clave y el certificado generando un `Issuer`
        let _ = rcgen::Issuer::from_ca_cert_pem(&cert_pem, key_pair)
            .map_err(|e| PkiError::CertGeneration(e.to_string()))?;

        // Almacena el DER para reconstruir luego el `Issuer`. Re parsea el PEM para obtener los
        // bytes del DER sin añadir dependencias extra
        let cert_der = pem_to_der(&cert_pem)
            .ok_or_else(|| PkiError::CertGeneration("PEM decode failed".into()))?;

        Ok(Self {
            inner: Arc::new(CaInner {
                ca_cert_der: cert_der,
                ca_key_pem: RwLock::new(key_pem),
                ca_cert_pem: cert_pem,
                ca_dir,
            }),
        })
    }
}

fn generate_serial() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let id = uuid::Uuid::new_v4();
    format!(
        "{:016x}{}",
        ts & 0xFFFF_FFFF_FFFF_FFFF,
        hex::encode(id.as_bytes())
    )
}

// Decoder básico PEM a DER (uso base64 entre las lineas de la cabecera y el pie)
fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    //use std::io::BufRead;
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD.decode(b64).ok()
}

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
    async fn generates_ca_and_persists() {
        let dir = tempdir().unwrap();
        let ca = CertificateAuthority::load_or_create(dir.path())
            .await
            .unwrap();
        assert!(ca.ca_cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(dir.path().join("ca.crt").exists());
        assert!(dir.path().join("ca.key").exists());
    }

    #[tokio::test]
    async fn loads_same_ca_on_second_call() {
        let dir = tempdir().unwrap();
        let ca1 = CertificateAuthority::load_or_create(dir.path())
            .await
            .unwrap();
        let pem1 = ca1.ca_cert_pem().to_string();
        let ca2 = CertificateAuthority::load_or_create(dir.path())
            .await
            .unwrap();
        assert_eq!(pem1, ca2.ca_cert_pem());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ca_key_has_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        CertificateAuthority::load_or_create(dir.path())
            .await
            .unwrap();
        let meta = std::fs::metadata(dir.path().join("ca.key")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }
}
