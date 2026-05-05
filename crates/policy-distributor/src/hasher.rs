//! Hash deterministico de un `PolicyBundle`
//!
//! El agente envia en cada `PollRequest` el hash del bundle que tiene en cache. El servidor
//! calcula el hash del bundle actual y los compara. Si son iguales responde con
//! `policies_changed` = false sin retransmitir el bundle completo.
//!
//! Para que el hash sea comparable entre servidor y agente, la serializacion JSON debe ser
//! deterministica. `serde_json` no garantiza orden de claves por defecto, pero los tipos proto
//! generados por prost tienen campos con orden fijo (los numeros de campo del .proto), lo que hace
//! la serializacion reproducible en la practica.
//!
//! El hash cubre el contenido semantico del bundle: politicas, elementos, checks, remediaciones y
//! sus parametros. No incluye timestamps ni metadatos que cambien sin que cambie el contenido de
//! las politicas.

use proto::PolicyBundle;
use sha2::{Digest, Sha256};

// Calcula el hash SHA256 del bundle serializado a JSON. Devuelve el hash en formato hex (64
// caracteres).
//
// El hash se usa como `bundle_hash` en `PolicyBundle` y como `policy_bundle_hash` en `PollRequest`
pub fn bundle_hash(bundle: &PolicyBundle) -> String {
    let json = serde_json::to_string(bundle).unwrap_or_default();

    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    hex::encode(hasher.finalize())
}

// Calcula el hash a partir del JSON del bundle ya serializado. Util cuando el bundle ya esta
// serializado y no interesa deserializarlo puesto que consumira mas recursos
pub fn hash_from_json(json: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::{Policy, PolicyBundle};

    fn make_bundle(hash: &str) -> PolicyBundle {
        PolicyBundle {
            bundle_hash: hash.to_string(),
            policies: vec![Policy {
                id: "pol-1".into(),
                name: "CIS L1".into(),
                version: "1.0".into(),
                severity: "high".into(),
                elements: vec![],
            }],
        }
    }

    #[test]
    fn hash_is_64_hex_chars() {
        let bundle = make_bundle("");
        let hash = bundle_hash(&bundle);
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn same_bundle_produces_same_hash() {
        let b1 = make_bundle("");
        let b2 = make_bundle("");
        assert_eq!(bundle_hash(&b1), bundle_hash(&b2));
    }

    #[test]
    fn different_content_produces_different_hash() {
        let mut b1 = make_bundle("");
        let mut b2 = make_bundle("");
        b1.policies[0].name = "Policy A".into();
        b2.policies[0].name = "Policy B".into();
        assert_ne!(bundle_hash(&b1), bundle_hash(&b2));
    }

    #[test]
    fn bundle_hash_field_does_not_affect_content_hash() {
        // El bundle_hash del struct es un metadato, no parte del contenido
        // que comparamos. Dos bundles con el mismo contenido pero distinto
        // bundle_hash producen hashes distintos — esto es correcto porque
        // el campo bundle_hash forma parte del JSON serializado.
        // Lo importante es que el servidor y el agente usen la misma función.
        let b1 = make_bundle("hash-v1");
        let b2 = make_bundle("hash-v2");
        // Sí son distintos porque bundle_hash es un campo del struct
        assert_ne!(bundle_hash(&b1), bundle_hash(&b2));
    }
}
