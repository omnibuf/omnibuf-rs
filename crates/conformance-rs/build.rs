use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let repo_root = manifest_dir.join("../..");
    let proto_root = repo_root.join("proto");
    let protos = [
        proto_root.join("omnibuf/bench/peer.proto"),
        proto_root.join("omnibuf/conformance/conformance.proto"),
    ];

    println!(
        "cargo:rerun-if-changed={}",
        repo_root.join("buf.yaml").display()
    );
    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto.display());
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let descriptor_path = out_dir.join("file_descriptor_set.bin");

    let built_with_buf = Command::new("buf")
        .current_dir(&repo_root)
        .args(["build", "-o"])
        .arg(&descriptor_path)
        .status()
        .is_ok_and(|s| s.success());

    let mut config = prost_build::Config::new();
    if built_with_buf {
        config.skip_protoc_run();
    }
    for msg in [
        "omnibuf.bench.Location",
        "omnibuf.bench.Neighbor",
        "omnibuf.bench.PeerUpdate",
        "omnibuf.conformance.AllTypesSubMsg",
        "omnibuf.conformance.TestAllTypes",
    ] {
        config.type_attribute(msg, "#[derive(::omnibuf::OmniBuf)]");
    }

    prost_reflect_build::Builder::new()
        .descriptor_pool("crate::proto_types::DESCRIPTOR_POOL")
        .file_descriptor_set_path(&descriptor_path)
        .configure(&mut config, &protos, &[&proto_root])?;

    config.compile_protos(&protos, &[&proto_root])?;

    Ok(())
}
