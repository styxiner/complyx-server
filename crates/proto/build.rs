//! Generación de código rust a partir de complyx.proto
//!
//! Este script se ejecuta por Cargo antes de compilar el crate.
//! Invoca tonic-build, que usa protoc para:
//! 1. Generar structs Rust de cada mensaje Protobuf via prost
//! 2. Genera los traits e implementaciones de los servicios gRPC via tonic
//!
//! El codigo generado se escribe en $OUT_DIR/complyx.rs y se incluye desde lib.rs
//!
//! IMPORTANTE:
//! Esto necesita requisitos adicionales para funcionar
//!
//! `protoc`: El compilador de Protocol Buffers debe estar instalado y disponible en el PATH.
//! Instalación:
//! Debian: sudo apt install -y protobuf-compiler
//! RHEL: sudo dnf install -y protobuf-compiler
//!
//! Configuración del agente vs servidor
//! Este crate pertenece al AGENTE:
//! * build_server(false): no genera los traits de servidor
//! * build_client(true): genera los stubs de cliente para ambos servicios
//!
//! El crate proto del servidor tiene la configuración inversa:
//! * build_server(true), build_client(false)

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let build_client = cfg!(feature = "client");
    let build_server = cfg!(feature = "server");
    
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let proto_dir = manifest.join("../../proto");
    let proto_file = proto_dir.join("complyx.proto");
    

    let mut prost_config = prost_build::Config::new();

    prost_config.type_attribute(
        ".",
        "#[derive(serde::Serialize, serde::Deserialize)]"
    );
    prost_config.type_attribute(
        ".",
        "#[serde(default)]"
        );

    tonic_build::configure()
        .build_server(build_server)
        .build_client(build_client)
        .compile_protos_with_config(
            prost_config,
            &[&proto_file],
            &[&proto_dir],
        )?;

    println!("cargo:rerun-if-changed=proto/complyx.proto");
    println!("cargo:rerun-if-changed=build.rs");

    Ok(())
}



