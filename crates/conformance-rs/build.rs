use std::env;
use std::fs;
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
    let editions_protos = [
        proto_root.join("omnibuf/conformance/editions_2023.proto"),
        proto_root.join("omnibuf/conformance/editions_2024.proto"),
        proto_root.join("omnibuf/conformance/editions_2026.proto"),
    ];

    println!(
        "cargo:rerun-if-changed={}",
        repo_root.join("buf.yaml").display()
    );
    for proto in protos.iter().chain(editions_protos.iter()) {
        println!("cargo:rerun-if-changed={}", proto.display());
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let descriptor_path = out_dir.join("file_descriptor_set.bin");
    let editions_descriptor_path = out_dir.join("editions_descriptor_set.bin");

    // Keep prost/prost-reflect descriptor set strictly proto3 (prost-reflect 0.16 cannot parse editions).
    let built_with_buf = Command::new("buf")
        .current_dir(&repo_root)
        .args([
            "build",
            "--path",
            "proto/omnibuf/bench/peer.proto",
            "--path",
            "proto/omnibuf/conformance/conformance.proto",
            "-o",
        ])
        .arg(&descriptor_path)
        .status()
        .is_ok_and(|s| s.success());

    // Build separate Editions 2023/2024/2026 FileDescriptorSet for buffa_descriptor::DescriptorPool.
    let editions_built_with_buf = Command::new("buf")
        .current_dir(&repo_root)
        .args([
            "build",
            "--path",
            "proto/omnibuf/conformance/editions_2023.proto",
            "--path",
            "proto/omnibuf/conformance/editions_2024.proto",
            "--path",
            "proto/omnibuf/conformance/editions_2026.proto",
            "-o",
        ])
        .arg(&editions_descriptor_path)
        .status()
        .is_ok_and(|s| s.success());
    if !editions_built_with_buf {
        let status = Command::new("protoc")
            .arg("-I")
            .arg(&proto_root)
            .arg("-o")
            .arg(&editions_descriptor_path)
            .args(&editions_protos)
            .status()?;
        if !status.success() {
            return Err("failed to compile Editions FileDescriptorSet via buf or protoc".into());
        }
    }

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

    buffa_build::Config::new()
        .descriptor_set(&descriptor_path)
        .files(&[
            "omnibuf/bench/peer.proto",
            "omnibuf/conformance/conformance.proto",
        ])
        .generate_views(true)
        .generate_reflection(true)
        .include_file("_buffa.rs")
        .message_attribute("omnibuf.bench.Location", "#[derive(::omnibuf::OmniBuf)]")
        .message_attribute("omnibuf.bench.Neighbor", "#[derive(::omnibuf::OmniBuf)]")
        .message_attribute("omnibuf.bench.PeerUpdate", "#[derive(::omnibuf::OmniBuf)]")
        .message_attribute(
            "omnibuf.conformance.AllTypesSubMsg",
            "#[derive(::omnibuf::OmniBuf)]",
        )
        .message_attribute(
            "omnibuf.conformance.TestAllTypes",
            "#[derive(::omnibuf::OmniBuf)]",
        )
        .field_attribute(
            "omnibuf.conformance.TestAllTypes.f15_fixed32",
            "#[omnibuf(wire = \"fixed32\")]",
        )
        .field_attribute(
            "omnibuf.conformance.TestAllTypes.f16_fixed64",
            "#[omnibuf(wire = \"fixed64\")]",
        )
        .compile()?;

    // Also generate buffa types for TreeNode, NestedCluster, enums, and oneofs in $OUT_DIR/buffa_extra
    // so integration tests exercise every buffa representation without modifying proto/.
    let extra_proto_root = out_dir.join("extra_proto");
    let extra_proto_file = extra_proto_root.join("omnibuf/extra/extra.proto");
    if let Some(parent) = extra_proto_file.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        &extra_proto_file,
        r#"syntax = "proto3";
package omnibuf.extra;

enum NodeRole {
  NODE_ROLE_UNSPECIFIED = 0;
  NODE_ROLE_LEAF = 1;
  NODE_ROLE_SPINE = 2;
}

message TreeNode {
  uint32 id = 1;
  string name = 2;
  sint64 weight = 3;
  TreeNode primary = 4;
  repeated TreeNode children = 5;
  repeated TreeNode branches = 6;
  map<string, uint64> labels = 7;
}

message NestedNIC {
  uint32 if_index = 1;
  string mac = 2;
  repeated uint32 ips = 3;
}

message NestedServer {
  uint32 server_id = 1;
  string hostname = 2;
  repeated NestedNIC nics = 3;
}

message NestedRack {
  uint32 rack_id = 1;
  string zone = 2;
  repeated NestedServer servers = 3;
}

message NestedCluster {
  string cluster_name = 1;
  repeated NestedRack racks = 2;
  uint64 epoch = 3;
}

message RouteEvent {
  NodeRole role = 1;
  repeated NodeRole history = 2;
  oneof payload {
    string text = 3;
    sint64 delta = 4;
    NestedNIC nic = 5;
  }
}
"#,
    )?;

    let extra_fds_path = out_dir.join("extra_file_descriptor_set.bin");
    let extra_built_with_buf = Command::new("buf")
        .args(["build"])
        .arg(&extra_proto_root)
        .arg("-o")
        .arg(&extra_fds_path)
        .status()
        .is_ok_and(|s| s.success());

    let extra_out_dir = out_dir.join("buffa_extra");
    fs::create_dir_all(&extra_out_dir)?;

    let mut extra_cfg = buffa_build::Config::new()
        .out_dir(&extra_out_dir)
        .generate_views(true)
        .generate_reflection(true)
        .include_file("mod.rs")
        .message_attribute("omnibuf.extra.TreeNode", "#[derive(::omnibuf::OmniBuf)]")
        .message_attribute("omnibuf.extra.NestedNIC", "#[derive(::omnibuf::OmniBuf)]")
        .message_attribute(
            "omnibuf.extra.NestedServer",
            "#[derive(::omnibuf::OmniBuf)]",
        )
        .message_attribute("omnibuf.extra.NestedRack", "#[derive(::omnibuf::OmniBuf)]")
        .message_attribute(
            "omnibuf.extra.NestedCluster",
            "#[derive(::omnibuf::OmniBuf)]",
        )
        .message_attribute("omnibuf.extra.RouteEvent", "#[derive(::omnibuf::OmniBuf)]")
        .oneof_attribute(
            "omnibuf.extra.RouteEvent.payload",
            "#[derive(::omnibuf::OmniBuf)]",
        )
        .field_attribute(
            "omnibuf.extra.RouteEvent.payload.text",
            "#[omnibuf(id = 3)]",
        )
        .field_attribute(
            "omnibuf.extra.RouteEvent.payload.delta",
            "#[omnibuf(id = 4)]",
        )
        .field_attribute("omnibuf.extra.RouteEvent.payload.nic", "#[omnibuf(id = 5)]");

    if extra_built_with_buf {
        extra_cfg = extra_cfg
            .descriptor_set(&extra_fds_path)
            .files(&["omnibuf/extra/extra.proto"]);
    } else {
        extra_cfg = extra_cfg
            .files(&[&extra_proto_file])
            .includes(&[&extra_proto_root]);
    }
    extra_cfg.compile()?;

    Ok(())
}
