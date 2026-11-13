use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use prost::Message as _;
use prost_types::FileDescriptorSet;
use prost_types::compiler::CodeGeneratorRequest;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir.join("../..");
    let proto_root = repo_root.join("proto");
    let peer_proto = proto_root.join("omnibuf/bench/peer.proto");

    println!(
        "cargo:rerun-if-changed={}",
        repo_root.join("buf.yaml").display()
    );
    println!("cargo:rerun-if-changed={}", peer_proto.display());

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let fds_path = out_dir.join("peer_descriptor_set.bin");

    let built_with_buf = Command::new("buf")
        .current_dir(&repo_root)
        .args(["build", "--path", "proto/omnibuf/bench/peer.proto", "-o"])
        .arg(&fds_path)
        .status()
        .is_ok_and(|s| s.success());

    let mut cfg = prost_build::Config::new();
    if built_with_buf {
        cfg.skip_protoc_run();
    }
    cfg.file_descriptor_set_path(&fds_path);
    cfg.compile_protos(&[&peer_proto], &[&proto_root])
        .expect("failed to compile peer.proto with prost-build");

    let fds_bytes = fs::read(&fds_path).expect("failed to read compiled FileDescriptorSet");
    let fds = FileDescriptorSet::decode(fds_bytes.as_slice())
        .expect("failed to decode FileDescriptorSet");

    let req = CodeGeneratorRequest {
        file_to_generate: vec!["omnibuf/bench/peer.proto".to_owned()],
        parameter: None,
        proto_file: fds.file,
        compiler_version: None,
    };

    let resp = protoc_gen_omnibuf_rs::generate(&req);
    if let Some(err) = resp.error {
        panic!("protoc-gen-omnibuf-rs failed: {err}");
    }
    for file in resp.file {
        let name = file.name.expect("generated file missing name");
        let content = file.content.expect("generated file missing content");
        fs::write(out_dir.join(name), content).expect("failed to write generated omnibuf file");
    }
}
