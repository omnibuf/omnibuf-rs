use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use prost::Message as _;
use prost_types::compiler::{CodeGeneratorRequest, CodeGeneratorResponse};
use prost_types::field_descriptor_proto::{Label, Type};
use prost_types::{
    DescriptorProto, EnumDescriptorProto, EnumValueDescriptorProto, FieldDescriptorProto,
    FileDescriptorProto, OneofDescriptorProto,
};
use protoc_gen_omnibuf_rs::generate_request_bytes;

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let id = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "omnibuf_editions_e2e_{prefix}_{}_{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn plugin_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_protoc-gen-omnibuf-rs"))
}

fn run_protoc_plugin(
    proto_dir: &Path,
    out_dir: &Path,
    proto_files: &[&str],
) -> std::process::Output {
    let mut cmd = Command::new("protoc");
    cmd.arg("-I")
        .arg(proto_dir)
        .arg(format!(
            "--plugin=protoc-gen-omnibuf-rs={}",
            plugin_bin().display()
        ))
        .arg(format!("--omnibuf-rs_out={}", out_dir.display()));
    for f in proto_files {
        cmd.arg(proto_dir.join(f));
    }
    cmd.output().expect("failed to execute protoc")
}

fn run_protoc_fds(proto_dir: &Path, fds_out: &Path, proto_files: &[&str]) -> Vec<u8> {
    let mut cmd = Command::new("protoc");
    cmd.arg("-I")
        .arg(proto_dir)
        .arg("--include_imports")
        .arg("-o")
        .arg(fds_out);
    for f in proto_files {
        cmd.arg(proto_dir.join(f));
    }
    let out = cmd.output().expect("failed to execute protoc");
    assert!(
        out.status.success(),
        "protoc descriptor build failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    fs::read(fds_out).expect("read fds output")
}

/// Decodes `minimum_edition` (#3) and `maximum_edition` (#4) directly from raw
/// `CodeGeneratorResponse` protobuf wire bytes, alongside standard fields.
fn decode_raw_response_editions(bytes: &[u8]) -> (CodeGeneratorResponse, Option<i32>, Option<i32>) {
    #[derive(Clone, PartialEq, prost::Message)]
    struct ResponseEditionFields {
        #[prost(int32, optional, tag = "3")]
        minimum_edition: Option<i32>,
        #[prost(int32, optional, tag = "4")]
        maximum_edition: Option<i32>,
    }
    let resp = CodeGeneratorResponse::decode(bytes).expect("decode CodeGeneratorResponse");
    let eds = ResponseEditionFields::decode(bytes).expect("decode edition bounds");
    (resp, eds.minimum_edition, eds.maximum_edition)
}

fn build_raw_editions_request(
    edition: Option<i32>,
    file_features_wire: &[u8],
    file_proto: FileDescriptorProto,
) -> Vec<u8> {
    let mut file_bytes = file_proto.encode_to_vec();
    if let Some(ed) = edition {
        // FileDescriptorProto.edition = field #14, wire type 0 (varint).
        file_bytes.push(14 << 3);
        let mut v = ed as u64;
        while v >= 0x80 {
            file_bytes.push(((v as u8) & 0x7F) | 0x80);
            v >>= 7;
        }
        file_bytes.push(v as u8);
    }
    if !file_features_wire.is_empty() {
        // FileDescriptorProto.options = field #8 (LEN) -> FileOptions.features = field #50 (LEN).
        let mut opts_bytes = Vec::new();
        let tag50 = (50u64 << 3) | 2;
        let mut t = tag50;
        while t >= 0x80 {
            opts_bytes.push(((t as u8) & 0x7F) | 0x80);
            t >>= 7;
        }
        opts_bytes.push(t as u8);
        let mut flen = file_features_wire.len() as u64;
        while flen >= 0x80 {
            opts_bytes.push(((flen as u8) & 0x7F) | 0x80);
            flen >>= 7;
        }
        opts_bytes.push(flen as u8);
        opts_bytes.extend_from_slice(file_features_wire);

        file_bytes.push((8 << 3) | 2);
        let mut olen = opts_bytes.len() as u64;
        while olen >= 0x80 {
            file_bytes.push(((olen as u8) & 0x7F) | 0x80);
            olen >>= 7;
        }
        file_bytes.push(olen as u8);
        file_bytes.extend_from_slice(&opts_bytes);
    }

    let mut req = CodeGeneratorRequest {
        file_to_generate: vec![file_proto.name.unwrap_or_else(|| "test.proto".to_owned())],
        parameter: None,
        compiler_version: None,
        proto_file: Vec::new(),
    }
    .encode_to_vec();
    // Append proto_file (field #15, wire type 2).
    req.push((15 << 3) | 2);
    let mut len = file_bytes.len() as u64;
    while len >= 0x80 {
        req.push(((len as u8) & 0x7F) | 0x80);
        len >>= 7;
    }
    req.push(len as u8);
    req.extend_from_slice(&file_bytes);
    req
}

#[test]
fn response_advertises_editions_2023_through_2026_and_rejects_unsupported_editions() {
    let base_file = FileDescriptorProto {
        name: Some("ver.proto".to_owned()),
        package: Some("ver.v1".to_owned()),
        syntax: Some("editions".to_owned()),
        message_type: vec![DescriptorProto {
            name: Some("Ping".to_owned()),
            field: vec![FieldDescriptorProto {
                name: Some("id".to_owned()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Uint32 as i32),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    };

    for supported in [1000, 1001, 1002] {
        let req = build_raw_editions_request(Some(supported), &[], base_file.clone());
        let resp_bytes = generate_request_bytes(&req).expect("generate_request_bytes");
        let (resp, min_ed, max_ed) = decode_raw_response_editions(&resp_bytes);
        assert!(
            resp.error.is_none(),
            "edition {supported} failed unexpectedly: {:?}",
            resp.error
        );
        assert_eq!(resp.supported_features, Some(3));
        assert_eq!(min_ed, Some(1000));
        assert_eq!(max_ed, Some(1002));
        let src = resp.file[0].content.as_deref().unwrap();
        assert!(
            src.contains("pub id: ::core::option::Option<u32>"),
            "edition {supported} should generate explicit Option<u32>"
        );
    }

    for unsupported in [None, Some(0), Some(998), Some(999), Some(1003), Some(9999)] {
        let req = build_raw_editions_request(unsupported, &[], base_file.clone());
        let resp_bytes = generate_request_bytes(&req).expect("generate_request_bytes");
        let (resp, min_ed, max_ed) = decode_raw_response_editions(&resp_bytes);
        let err = resp
            .error
            .expect("expected unsupported edition to return error");
        assert!(
            err.contains("unsupported protobuf edition"),
            "unexpected error for edition {unsupported:?}: {err}"
        );
        assert_eq!(resp.supported_features, Some(3));
        assert_eq!(min_ed, Some(1000));
        assert_eq!(max_ed, Some(1002));
    }
}

#[test]
fn synthetic_feature_inheritance_and_type_group_normalization_in_editions() {
    // Build a synthetic Editions 2026 request with:
    // - file features: field_presence = IMPLICIT (2)
    // - message features: field_presence = EXPLICIT (1)
    // - nested field #1: inherits EXPLICIT -> Option<i32>
    // - nested field #2: field override IMPLICIT -> i32
    // - nested field #3: TYPE_GROUP in Editions -> converted to TYPE_MESSAGE (Option<Child>)
    // - oneof with OneofOptions.features.utf8_validation = NONE on a string -> rejected!
    #[derive(Clone, PartialEq, prost::Message)]
    struct Feat {
        #[prost(int32, optional, tag = "1")]
        presence: Option<i32>,
        #[prost(int32, optional, tag = "4")]
        utf8: Option<i32>,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    struct MsgOpts {
        #[prost(message, optional, tag = "12")]
        features: Option<Feat>,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    struct FldOpts {
        #[prost(message, optional, tag = "21")]
        features: Option<Feat>,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    struct OneofOpts {
        #[prost(message, optional, tag = "1")]
        features: Option<Feat>,
    }

    fn append_len_field(dst: &mut Vec<u8>, tag_num: u32, payload: &[u8]) {
        let tag = (u64::from(tag_num) << 3) | 2;
        let mut t = tag;
        while t >= 0x80 {
            dst.push(((t as u8) & 0x7F) | 0x80);
            t >>= 7;
        }
        dst.push(t as u8);
        let mut l = payload.len() as u64;
        while l >= 0x80 {
            dst.push(((l as u8) & 0x7F) | 0x80);
            l >>= 7;
        }
        dst.push(l as u8);
        dst.extend_from_slice(payload);
    }

    // Build message Child (#1)
    let child_bytes = DescriptorProto {
        name: Some("Child".to_owned()),
        field: vec![FieldDescriptorProto {
            name: Some("x".to_owned()),
            number: Some(1),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::Int32 as i32),
            ..Default::default()
        }],
        ..Default::default()
    }
    .encode_to_vec();

    // Build message Parent with message_options.features.presence = EXPLICIT
    let mut f2_bytes = FieldDescriptorProto {
        name: Some("imp_override".to_owned()),
        number: Some(2),
        label: Some(Label::Optional as i32),
        r#type: Some(Type::Int32 as i32),
        ..Default::default()
    }
    .encode_to_vec();
    append_len_field(
        &mut f2_bytes,
        8,
        &FldOpts {
            features: Some(Feat {
                presence: Some(2),
                utf8: None,
            }),
        }
        .encode_to_vec(),
    );

    let mut parent_bytes = DescriptorProto {
        name: Some("Parent".to_owned()),
        field: vec![
            FieldDescriptorProto {
                name: Some("exp_from_msg".to_owned()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Int32 as i32),
                ..Default::default()
            },
            FieldDescriptorProto {
                name: Some("grp_child".to_owned()),
                number: Some(3),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Group as i32),
                type_name: Some(".inh.v1.Child".to_owned()),
                ..Default::default()
            },
        ],
        ..Default::default()
    }
    .encode_to_vec();
    append_len_field(&mut parent_bytes, 2, &f2_bytes);
    append_len_field(
        &mut parent_bytes,
        7,
        &MsgOpts {
            features: Some(Feat {
                presence: Some(1),
                utf8: None,
            }),
        }
        .encode_to_vec(),
    );

    let mut file_bytes = FileDescriptorProto {
        name: Some("inh.proto".to_owned()),
        package: Some("inh.v1".to_owned()),
        syntax: Some("editions".to_owned()),
        ..Default::default()
    }
    .encode_to_vec();
    append_len_field(&mut file_bytes, 4, &child_bytes);
    append_len_field(&mut file_bytes, 4, &parent_bytes);
    // edition = 1002 (EDITION_2026)
    file_bytes.extend_from_slice(&[0x70, 0xea, 0x07]);
    // file options: presence = IMPLICIT (2)
    let mut file_opts = Vec::new();
    append_len_field(
        &mut file_opts,
        50,
        &Feat {
            presence: Some(2),
            utf8: None,
        }
        .encode_to_vec(),
    );
    append_len_field(&mut file_bytes, 8, &file_opts);

    let mut req = CodeGeneratorRequest {
        file_to_generate: vec!["inh.proto".to_owned()],
        ..Default::default()
    }
    .encode_to_vec();
    append_len_field(&mut req, 15, &file_bytes);

    let resp_bytes = generate_request_bytes(&req).expect("generate_request_bytes");
    let (resp, _, _) = decode_raw_response_editions(&resp_bytes);
    assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
    let src = resp.file[0].content.as_deref().unwrap();
    // Child inherits file-level IMPLICIT -> plain i32
    assert!(src.contains("pub struct Child {\n    pub x: i32,"));
    // Parent overrides message-level EXPLICIT -> Option<i32>, field-level override -> i32, TYPE_GROUP -> Option<Child>
    assert!(src.contains("pub exp_from_msg: ::core::option::Option<i32>"));
    assert!(src.contains("pub imp_override: i32"));
    assert!(src.contains("pub grp_child: ::core::option::Option<Child>"));

    // Oneof feature inheritance: OneofOptions.features.utf8_validation = NONE on string arm must fail!
    let mut oneof_bytes = OneofDescriptorProto {
        name: Some("choice".to_owned()),
        options: None,
    }
    .encode_to_vec();
    append_len_field(
        &mut oneof_bytes,
        2,
        &OneofOpts {
            features: Some(Feat {
                presence: None,
                utf8: Some(3),
            }),
        }
        .encode_to_vec(),
    );
    let mut bad_msg = DescriptorProto {
        name: Some("BadOneof".to_owned()),
        field: vec![FieldDescriptorProto {
            name: Some("raw_str".to_owned()),
            number: Some(1),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::String as i32),
            oneof_index: Some(0),
            ..Default::default()
        }],
        ..Default::default()
    }
    .encode_to_vec();
    append_len_field(&mut bad_msg, 8, &oneof_bytes);

    let mut bad_file = FileDescriptorProto {
        name: Some("bad_oneof.proto".to_owned()),
        syntax: Some("editions".to_owned()),
        ..Default::default()
    }
    .encode_to_vec();
    append_len_field(&mut bad_file, 4, &bad_msg);
    bad_file.extend_from_slice(&[0x70, 0xe8, 0x07]); // edition 2023

    let mut bad_req = CodeGeneratorRequest {
        file_to_generate: vec!["bad_oneof.proto".to_owned()],
        ..Default::default()
    }
    .encode_to_vec();
    append_len_field(&mut bad_req, 15, &bad_file);

    let bad_resp_bytes = generate_request_bytes(&bad_req).expect("generate_request_bytes");
    let (bad_resp, _, _) = decode_raw_response_editions(&bad_resp_bytes);
    assert!(
        bad_resp
            .error
            .as_deref()
            .is_some_and(|e| e.contains("utf8_validation")),
        "expected oneof utf8_validation = NONE rejection, got: {:?}",
        bad_resp.error
    );
}

#[test]
fn real_protoc_negative_editions_rejections() {
    type NegativeCase<'a> = (&'a str, &'a [(&'a str, &'a str)], &'a str, &'a str);
    let cases: &[NegativeCase<'_>] = &[
        (
            "closed_file_enum",
            &[(
                "closed_file.proto",
                r#"
edition = "2023";
package neg.cf;
option features.enum_type = CLOSED;
enum Bad {
  BAD_ZERO = 0;
}
message M { Bad b = 1; }
"#,
            )],
            "closed_file.proto",
            "CLOSED",
        ),
        (
            "closed_nested_enum",
            &[(
                "closed_nested.proto",
                r#"
edition = "2024";
package neg.cn;
message M {
  enum Inner {
    option features.enum_type = CLOSED;
    INNER_ZERO = 0;
  }
  Inner i = 1;
}
"#,
            )],
            "closed_nested.proto",
            "CLOSED",
        ),
        (
            "imported_proto2_closed_enum",
            &[
                (
                    "legacy_enum.proto",
                    r#"
syntax = "proto2";
package neg.p2;
enum LegacyClosed {
  LEGACY_ZERO = 0;
  LEGACY_ONE = 1;
}
"#,
                ),
                (
                    "uses_legacy.proto",
                    r#"
edition = "2026";
package neg.edp2;
import "legacy_enum.proto";
export message UsesLegacy {
  neg.p2.LegacyClosed e = 1;
}
"#,
                ),
            ],
            "uses_legacy.proto",
            "CLOSED",
        ),
        (
            "legacy_required",
            &[(
                "req.proto",
                r#"
edition = "2023";
package neg.req;
message M {
  int32 must_set = 1 [features.field_presence = LEGACY_REQUIRED];
}
"#,
            )],
            "req.proto",
            "LEGACY_REQUIRED",
        ),
        (
            "utf8_none_singular",
            &[(
                "utf8_s.proto",
                r#"
edition = "2023";
package neg.u1;
message M {
  string raw = 1 [features.utf8_validation = NONE];
}
"#,
            )],
            "utf8_s.proto",
            "utf8_validation",
        ),
        (
            "utf8_none_repeated",
            &[(
                "utf8_rep.proto",
                r#"
edition = "2024";
package neg.u2;
message M {
  repeated string raws = 1 [features.utf8_validation = NONE];
}
"#,
            )],
            "utf8_rep.proto",
            "utf8_validation",
        ),
        (
            "utf8_none_map_key",
            &[(
                "utf8_mk.proto",
                r#"
edition = "2023";
package neg.u3;
message M {
  map<string, int32> scores = 1 [features.utf8_validation = NONE];
}
"#,
            )],
            "utf8_mk.proto",
            "utf8_validation",
        ),
        (
            "utf8_none_map_val_file_level",
            &[(
                "utf8_mv.proto",
                r#"
edition = "2026";
package neg.u4;
option features.utf8_validation = NONE;
export message M {
  map<int32, string> labels = 1;
}
"#,
            )],
            "utf8_mv.proto",
            "utf8_validation",
        ),
        (
            "nonzero_default_int",
            &[(
                "def_int.proto",
                r#"
edition = "2023";
package neg.d1;
message M {
  int32 retries = 1 [default = 3];
}
"#,
            )],
            "def_int.proto",
            "default",
        ),
        (
            "nonzero_default_enum",
            &[(
                "def_enum.proto",
                r#"
edition = "2024";
package neg.d2;
enum Mode {
  MODE_UNSPECIFIED = 0;
  MODE_FAST = 1;
}
message M {
  Mode mode = 1 [default = MODE_FAST];
}
"#,
            )],
            "def_enum.proto",
            "default",
        ),
        (
            "nonzero_default_string",
            &[(
                "def_str.proto",
                r#"
edition = "2026";
package neg.d3;
export message M {
  string name = 1 [default = "guest"];
}
"#,
            )],
            "def_str.proto",
            "default",
        ),
        (
            "non_option_extension",
            &[(
                "ext.proto",
                r#"
edition = "2023";
package neg.ext;
message Extendable {
  int32 id = 1;
  extensions 100 to 200;
}
extend Extendable {
  string extra = 100;
}
"#,
            )],
            "ext.proto",
            "extension",
        ),
    ];

    for (label, files, target, expected_err) in cases {
        let tmp = TempDir::new(label);
        let out_dir = tmp.path().join("out");
        fs::create_dir_all(&out_dir).unwrap();
        for (name, content) in *files {
            fs::write(tmp.path().join(name), content).unwrap();
        }
        let out = run_protoc_plugin(tmp.path(), &out_dir, &[target]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "case {label} unexpectedly succeeded");
        assert!(
            stderr.contains(expected_err),
            "case {label}: expected stderr containing {expected_err:?}, got:\n{stderr}"
        );
    }

    // Sanity-check: synthetic enum with CLOSED enum referenced in map value is also rejected.
    let closed_p2_file = FileDescriptorProto {
        name: Some("p2.proto".to_owned()),
        package: Some("p2".to_owned()),
        syntax: Some("proto2".to_owned()),
        enum_type: vec![EnumDescriptorProto {
            name: Some("ClosedE".to_owned()),
            value: vec![EnumValueDescriptorProto {
                name: Some("ZERO".to_owned()),
                number: Some(0),
                options: None,
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let ed_file = FileDescriptorProto {
        name: Some("ed.proto".to_owned()),
        package: Some("ed".to_owned()),
        syntax: Some("editions".to_owned()),
        dependency: vec!["p2.proto".to_owned()],
        message_type: vec![DescriptorProto {
            name: Some("M".to_owned()),
            field: vec![FieldDescriptorProto {
                name: Some("m".to_owned()),
                number: Some(1),
                label: Some(Label::Repeated as i32),
                r#type: Some(Type::Message as i32),
                type_name: Some(".ed.M.MEntry".to_owned()),
                ..Default::default()
            }],
            nested_type: vec![DescriptorProto {
                name: Some("MEntry".to_owned()),
                options: Some(prost_types::MessageOptions {
                    map_entry: Some(true),
                    ..Default::default()
                }),
                field: vec![
                    FieldDescriptorProto {
                        name: Some("key".to_owned()),
                        number: Some(1),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::String as i32),
                        ..Default::default()
                    },
                    FieldDescriptorProto {
                        name: Some("value".to_owned()),
                        number: Some(2),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::Enum as i32),
                        type_name: Some(".p2.ClosedE".to_owned()),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut req = CodeGeneratorRequest {
        file_to_generate: vec!["ed.proto".to_owned()],
        proto_file: vec![closed_p2_file],
        ..Default::default()
    }
    .encode_to_vec();
    let mut ed_bytes = ed_file.encode_to_vec();
    ed_bytes.extend_from_slice(&[0x70, 0xe8, 0x07]); // edition 2023
    req.push((15 << 3) | 2);
    let mut l = ed_bytes.len() as u64;
    while l >= 0x80 {
        req.push(((l as u8) & 0x7F) | 0x80);
        l >>= 7;
    }
    req.push(l as u8);
    req.extend_from_slice(&ed_bytes);
    let resp_bytes = generate_request_bytes(&req).expect("generate_request_bytes");
    let (resp, _, _) = decode_raw_response_editions(&resp_bytes);
    assert!(
        resp.error.as_deref().is_some_and(|e| e.contains("CLOSED")),
        "expected CLOSED enum rejection on map value, got: {:?}",
        resp.error
    );
}

#[test]
fn real_protoc_editions_2023_2024_2026_compile_and_execute_end_to_end() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let omnibuf_crate = workspace_root.join("crates/omnibuf");
    assert!(
        omnibuf_crate.join("Cargo.toml").exists(),
        "expected workspace crates/omnibuf"
    );

    let tmp = TempDir::new("full_e2e");
    let proto_dir = tmp.path().join("proto");
    let gen_dir = tmp.path().join("src/generated");
    let desc_dir = tmp.path().join("desc");
    fs::create_dir_all(&proto_dir).unwrap();
    fs::create_dir_all(&gen_dir).unwrap();
    fs::create_dir_all(&desc_dir).unwrap();

    // Option extension proto (allowed: extends google.protobuf.MessageOptions).
    fs::write(
        proto_dir.join("custom_opts.proto"),
        r#"edition = "2024";
package opts.v1;
import "google/protobuf/descriptor.proto";

extend google.protobuf.MessageOptions {
  string note = 50001;
}
"#,
    )
    .unwrap();

    // Edition 2023 comprehensive schema.
    fs::write(
        proto_dir.join("ed2023.proto"),
        r#"edition = "2023";
package ed23.v1;

enum Status {
  STATUS_UNSPECIFIED = 0;
  STATUS_ACTIVE = 1;
  STATUS_PAUSED = 2;
}

message Child {
  int32 id = 1 [default = 0];
  string label = 2 [default = ""];
}

message Record2023 {
  int32 exp_i32 = 1 [default = 0];
  bool exp_bool = 2 [default = false];
  string exp_str = 3 [default = ""];
  bytes exp_bytes = 4 [default = ""];
  float exp_f32 = 5 [default = 0.0];
  double exp_f64 = 6 [default = 0.0];
  Status exp_status = 7 [default = STATUS_UNSPECIFIED];
  int32 imp_i32 = 8 [features.field_presence = IMPLICIT];
  repeated int32 packed_nums = 9 [features.repeated_field_encoding = PACKED];
  repeated int32 expanded_nums = 10 [features.repeated_field_encoding = EXPANDED];
  map<string, int32> scores = 11;
  map<string, Child> children = 12;
  Child nested = 13;
  Child delim_child = 14 [features.message_encoding = DELIMITED];
  repeated Child delim_list = 15 [features.message_encoding = DELIMITED];
}

message Choice2023 {
  int32 header = 1;
  oneof payload {
    int32 num = 2;
    bool flag = 3;
    string text = 4;
    Child child = 5;
    Child delim_arm = 6 [features.message_encoding = DELIMITED];
  }
}

message FileImplicit2023 {
  int32 imp_a = 1 [features.field_presence = IMPLICIT];
  string imp_s = 2 [features.field_presence = IMPLICIT];
}
"#,
    )
    .unwrap();

    // Edition 2023 file-level IMPLICIT with field-level EXPLICIT override.
    fs::write(
        proto_dir.join("ed2023_imp.proto"),
        r#"edition = "2023";
package ed23imp.v1;

option features.field_presence = IMPLICIT;
option features.repeated_field_encoding = EXPANDED;

message Override2023 {
  int32 file_imp = 1;
  int32 field_exp = 2 [features.field_presence = EXPLICIT];
  repeated int32 file_expanded = 3;
  repeated int32 field_packed = 4 [features.repeated_field_encoding = PACKED];
}
"#,
    )
    .unwrap();

    // Edition 2024 schema exercising source-only 2024 features + import option + STRICT visibility + export/local.
    fs::write(
        proto_dir.join("ed2024.proto"),
        r#"edition = "2024";
package ed24.v1;

import option "custom_opts.proto";

option features.default_symbol_visibility = STRICT;
option features.enforce_naming_style = STYLE2024;
option features.json_format = LEGACY_BEST_EFFORT;

export enum Priority {
  PRIORITY_UNSPECIFIED = 0;
  PRIORITY_HIGH = 1;
}

local message Detail2024 {
  int32 code = 1;
  string info = 2;
}

export message Record2024 {
  option (opts.v1.note) = "ed2024-record";
  int32 exp_num = 1;
  bool exp_flag = 2;
  string imp_name = 3 [features.field_presence = IMPLICIT];
  Priority prio = 4;
  Detail2024 delim_detail = 5 [features.message_encoding = DELIMITED];
  repeated Detail2024 delim_details = 6 [features.message_encoding = DELIMITED];
  map<string, int32> counts = 7;
}

export message Choice2024 {
  oneof pick {
    int32 zero_or_num = 1;
    bool flag = 2;
    Detail2024 detail = 3;
  }
}
"#,
    )
    .unwrap();

    // Edition 2026 schema exercising 2026 default STRICT visibility + enforce_proto_limits + STYLE2026.
    fs::write(
        proto_dir.join("ed2026.proto"),
        r#"edition = "2026";
package ed26.v1;

option features.enforce_naming_style = STYLE2026;

export enum Tier {
  TIER_UNSPECIFIED = 0;
  TIER_EDGE = 1;
  TIER_CORE = 2;
}

local message Meta2026 {
  option features.enforce_proto_limits = PROTO_LIMITS2026;
  int32 seq = 1;
  string tag = 2;
}

export message Record2026 {
  option features.enforce_proto_limits = PROTO_LIMITS2026;
  int32 exp_id = 1;
  bool exp_ok = 2;
  string exp_msg = 3;
  bytes exp_raw = 4;
  Tier tier = 5;
  int32 imp_counter = 6 [features.field_presence = IMPLICIT];
  repeated int32 packed_vals = 7 [features.repeated_field_encoding = PACKED];
  repeated int32 expanded_vals = 8 [features.repeated_field_encoding = EXPANDED];
  map<string, int32> weights = 9;
  map<string, Meta2026> metas = 10;
  Meta2026 delim_meta = 11 [features.message_encoding = DELIMITED];
  repeated Meta2026 delim_metas = 12 [features.message_encoding = DELIMITED];
}

export message Choice2026 {
  int32 tag = 1;
  oneof branch {
    int32 code = 2;
    bool active = 3;
    string reason = 4;
    Meta2026 meta = 5 [features.message_encoding = DELIMITED];
  }
}
"#,
    )
    .unwrap();

    let all_protos = [
        "ed2023.proto",
        "ed2023_imp.proto",
        "ed2024.proto",
        "ed2026.proto",
    ];
    let out = run_protoc_plugin(&proto_dir, &gen_dir, &all_protos);
    assert!(
        out.status.success(),
        "protoc plugin failed on Editions 2023/2024/2026:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // Emit FileDescriptorSets for buffa_codec cross-tier wire-equivalence verification.
    let _ = run_protoc_fds(&proto_dir, &desc_dir.join("ed2023.pb"), &["ed2023.proto"]);
    let _ = run_protoc_fds(&proto_dir, &desc_dir.join("ed2024.pb"), &["ed2024.proto"]);
    let _ = run_protoc_fds(&proto_dir, &desc_dir.join("ed2026.pb"), &["ed2026.proto"]);

    // Verify custom_opts.proto (option extension only) also passes protoc-gen-omnibuf-rs.
    let opt_out = run_protoc_plugin(&proto_dir, &gen_dir, &["custom_opts.proto"]);
    assert!(
        opt_out.status.success(),
        "option extension proto should succeed, stderr:\n{}",
        String::from_utf8_lossy(&opt_out.stderr)
    );

    // Create a self-contained offline Cargo package that compiles and runs all generated Rust code.
    let cargo_toml = format!(
        r#"[package]
name = "editions-e2e-runner"
version = "0.1.0"
edition = "2024"

[dependencies]
omnibuf = {{ path = {:?} }}
buffa-descriptor = {{ version = "0.9", features = ["reflect", "std"] }}
"#,
        omnibuf_crate
    );
    fs::write(tmp.path().join("Cargo.toml"), cargo_toml).unwrap();
    fs::copy(
        workspace_root.join("Cargo.lock"),
        tmp.path().join("Cargo.lock"),
    )
    .unwrap();

    fs::write(
        tmp.path().join("src/main.rs"),
        r#"#![allow(dead_code)]

mod generated {
    pub mod ed2023_omnibuf;
    pub mod ed2023_imp_omnibuf;
    pub mod ed2024_omnibuf;
    pub mod ed2026_omnibuf;
}

use std::collections::HashMap;
use std::sync::Arc;

use buffa_descriptor::{
    DescriptorPool, DynamicMessage, MapKey, MapValue, ReflectMessage, ReflectMessageMut, Value,
};
use generated::ed2023_imp_omnibuf::Override2023;
use generated::ed2023_omnibuf::{
    Child, Choice2023, Choice2023Borrowed, Choice2023Payload, Choice2023PayloadBorrowed,
    OpaqueRecord2023, Record2023, Record2023Borrowed, Status,
};
use generated::ed2024_omnibuf::{
    Choice2024, Choice2024Pick, Detail2024, OpaqueRecord2024, Priority, Record2024,
};
use generated::ed2026_omnibuf::{
    Choice2026, Choice2026Branch, Meta2026, OpaqueRecord2026, Record2026, Tier,
};
use omnibuf::buffa_codec::{decode_buffa_dynamic, encode_buffa_dynamic};
use omnibuf::{DecodeBorrowed, EncodeOptions, Message};

fn test_edition_2023() {
    // 1. Absent vs explicit zero/false/empty/enum-0.
    let absent = Record2023::default();
    let explicit_zero = Record2023 {
        exp_i32: Some(0),
        exp_bool: Some(false),
        exp_str: Some(String::new()),
        exp_bytes: Some(Vec::new()),
        exp_f32: Some(0.0),
        exp_f64: Some(-0.0),
        exp_status: Some(Status::StatusUnspecified as i32),
        ..Default::default()
    };
    let wire_absent = absent.marshal_omnibuf();
    let wire_zero = explicit_zero.marshal_omnibuf();
    assert_ne!(
        wire_absent, wire_zero,
        "absent and explicit-zero must produce distinct wire bytes"
    );

    let rt_absent = Record2023::from_omnibuf(&wire_absent).unwrap();
    assert_eq!(rt_absent.exp_i32, None);
    assert_eq!(rt_absent.exp_bool, None);
    assert_eq!(rt_absent.exp_str, None);
    assert_eq!(rt_absent.exp_bytes, None);
    assert_eq!(rt_absent.exp_f32, None);
    assert_eq!(rt_absent.exp_f64, None);
    assert_eq!(rt_absent.exp_status, None);

    let rt_zero = Record2023::from_omnibuf(&wire_zero).unwrap();
    assert_eq!(rt_zero.exp_i32, Some(0));
    assert_eq!(rt_zero.exp_bool, Some(false));
    assert_eq!(rt_zero.exp_str.as_deref(), Some(""));
    assert_eq!(rt_zero.exp_bytes.as_deref(), Some(&[][..]));
    assert_eq!(rt_zero.exp_f32.map(f32::to_bits), Some(0.0_f32.to_bits()));
    assert_eq!(rt_zero.exp_f64.map(f64::to_bits), Some((-0.0_f64).to_bits()));
    assert_eq!(rt_zero.exp_status, Some(0));

    // Borrowed view also distinguishes absent vs explicit zero/false/empty.
    let b_absent = Record2023Borrowed::from_omnibuf_borrowed(&wire_absent).unwrap();
    assert_eq!(b_absent.exp_i32, None);
    assert_eq!(b_absent.exp_bool, None);
    assert_eq!(b_absent.exp_str, None);
    assert_eq!(b_absent.exp_bytes, None);
    let b_zero = Record2023Borrowed::from_omnibuf_borrowed(&wire_zero).unwrap();
    assert_eq!(b_zero.exp_i32, Some(0));
    assert_eq!(b_zero.exp_bool, Some(false));
    assert_eq!(b_zero.exp_str, Some(""));
    assert_eq!(b_zero.exp_bytes, Some(&[][..]));

    // 2. Full message with unknown open enum, packed/expanded, maps, nested & delimited messages.
    let mut scores = HashMap::new();
    scores.insert("alpha".to_owned(), 10);
    scores.insert("zero".to_owned(), 0);
    let mut children = HashMap::new();
    children.insert(
        "c1".to_owned(),
        Child {
            id: Some(7),
            label: Some("first".to_owned()),
        },
    );
    let full = Record2023 {
        exp_i32: Some(-42),
        exp_bool: Some(true),
        exp_str: Some("hello".to_owned()),
        exp_bytes: Some(vec![1, 2, 3]),
        exp_f32: Some(1.5),
        exp_f64: Some(-2.25),
        exp_status: Some(999), // unknown open enum value preserved
        imp_i32: 55,
        packed_nums: vec![1, -2, 3],
        expanded_nums: vec![4, 0, -5],
        scores,
        children,
        nested: Some(Child {
            id: Some(0),
            label: Some(String::new()),
        }),
        delim_child: Some(Child {
            id: Some(88),
            label: Some("delim".to_owned()),
        }),
        delim_list: vec![
            Child {
                id: Some(10),
                label: Some("d1".to_owned()),
            },
            Child {
                id: None,
                label: Some("d2".to_owned()),
            },
        ],
    };
    let wire_full = full.marshal_omnibuf();
    let rt_full = Record2023::from_omnibuf(&wire_full).unwrap();
    assert_eq!(rt_full, full);
    assert_eq!(rt_full.exp_status, Some(999));

    // 3. OpaqueRecord2023: absent vs present-zero, mutating to explicit zero/false/empty vs clearing.
    let mut op_absent = OpaqueRecord2023::try_new(&wire_absent).unwrap();
    assert!(!op_absent.has_exp_i32());
    assert!(!op_absent.has_exp_bool());
    assert!(!op_absent.has_exp_str());
    assert!(!op_absent.has_exp_bytes());
    assert!(!op_absent.has_exp_status());
    assert!(!op_absent.has_delim_child());

    let op_zero = OpaqueRecord2023::try_new(&wire_zero).unwrap();
    assert!(op_zero.has_exp_i32());
    assert_eq!(op_zero.get_exp_i32(), 0);
    assert!(op_zero.has_exp_bool());
    assert!(!op_zero.get_exp_bool());
    assert!(op_zero.has_exp_str());
    assert_eq!(op_zero.get_exp_str(), "");
    assert!(op_zero.has_exp_bytes());
    assert_eq!(op_zero.get_exp_bytes(), &[]);
    assert!(op_zero.has_exp_status());
    assert_eq!(op_zero.get_exp_status(), 0);

    // Mutate absent -> explicit zero/false/empty and splice.
    op_absent.set_exp_i32(Some(0));
    op_absent.set_exp_bool(Some(false));
    op_absent.set_exp_str(Some(String::new()));
    op_absent.set_exp_bytes(Some(Vec::new()));
    op_absent.set_exp_status(Some(0));
    let spliced_to_zero = op_absent.try_marshal().unwrap();
    let dec_spliced = Record2023::from_omnibuf(&spliced_to_zero).unwrap();
    assert_eq!(dec_spliced.exp_i32, Some(0));
    assert_eq!(dec_spliced.exp_bool, Some(false));
    assert_eq!(dec_spliced.exp_str.as_deref(), Some(""));
    assert_eq!(dec_spliced.exp_bytes.as_deref(), Some(&[][..]));
    assert_eq!(dec_spliced.exp_status, Some(0));

    // Mutate present -> cleared (None) and splice.
    let mut op_full = OpaqueRecord2023::try_new(&wire_full).unwrap();
    assert!(op_full.has_delim_child());
    assert_eq!(op_full.get_delim_child().get_id(), 88);
    assert_eq!(op_full.delim_list_len(), 2);
    assert_eq!(op_full.get_delim_list(0).get_label(), "d1");
    op_full.set_exp_i32(None);
    op_full.set_exp_bool(None);
    op_full.set_exp_str(None);
    op_full.set_delim_child(None);
    let spliced_cleared = op_full.try_marshal().unwrap();
    let dec_cleared = Record2023::from_omnibuf(&spliced_cleared).unwrap();
    assert_eq!(dec_cleared.exp_i32, None);
    assert_eq!(dec_cleared.exp_bool, None);
    assert_eq!(dec_cleared.exp_str, None);
    assert_eq!(dec_cleared.delim_child, None);
    assert_eq!(dec_cleared.exp_status, Some(999));

    // 4. Oneofs (including active zero/false/empty & delimited arm & switching branches).
    let c_zero = Choice2023 {
        header: Some(1),
        payload: Some(Choice2023Payload::Num(0)),
    };
    let c_false = Choice2023 {
        header: Some(1),
        payload: Some(Choice2023Payload::Flag(false)),
    };
    let c_empty_str = Choice2023 {
        header: None,
        payload: Some(Choice2023Payload::Text(String::new())),
    };
    let c_delim = Choice2023 {
        header: Some(2),
        payload: Some(Choice2023Payload::DelimArm(Child {
            id: Some(77),
            label: Some("arm".to_owned()),
        })),
    };
    assert_eq!(
        Choice2023::from_omnibuf(&c_zero.marshal_omnibuf()).unwrap(),
        c_zero
    );
    assert_eq!(
        Choice2023::from_omnibuf(&c_false.marshal_omnibuf()).unwrap(),
        c_false
    );
    let empty_wire = c_empty_str.marshal_omnibuf();
    assert_eq!(Choice2023::from_omnibuf(&empty_wire).unwrap(), c_empty_str);
    let b_empty = Choice2023Borrowed::from_omnibuf_borrowed(&empty_wire).unwrap();
    assert_eq!(b_empty.payload, Some(Choice2023PayloadBorrowed::Text("")));
    assert_eq!(
        Choice2023::from_omnibuf(&c_delim.marshal_omnibuf()).unwrap(),
        c_delim
    );

    // Branch switching: concat wire(c_zero) + wire(c_delim) -> last branch wins.
    let mut switched = c_zero.marshal_omnibuf();
    switched.extend_from_slice(&c_delim.marshal_omnibuf());
    assert_eq!(Choice2023::from_omnibuf(&switched).unwrap(), c_delim);

    // 5. File-level IMPLICIT + field-level EXPLICIT override.
    let ov_absent = Override2023 {
        file_imp: 0,
        field_exp: None,
        file_expanded: vec![1, 2],
        field_packed: vec![3, 4],
    };
    let ov_present_zero = Override2023 {
        file_imp: 0,
        field_exp: Some(0),
        file_expanded: vec![1, 2],
        field_packed: vec![3, 4],
    };
    assert_ne!(ov_absent.marshal_omnibuf(), ov_present_zero.marshal_omnibuf());
    assert_eq!(
        Override2023::from_omnibuf(&ov_absent.marshal_omnibuf()).unwrap(),
        ov_absent
    );
    assert_eq!(
        Override2023::from_omnibuf(&ov_present_zero.marshal_omnibuf()).unwrap(),
        ov_present_zero
    );

    // 6. Byte-for-byte wire equivalence with buffa_codec on real protoc 36.2 Edition 2023 FDS!
    let fds_bytes = include_bytes!("../desc/ed2023.pb");
    let pool = Arc::new(DescriptorPool::decode(fds_bytes).unwrap());
    let rec_idx = pool.message_index("ed23.v1.Record2023").unwrap();
    let child_idx = pool.message_index("ed23.v1.Child").unwrap();
    let md = pool.message(rec_idx);
    let cmd = pool.message(child_idx);

    let mut dmsg = DynamicMessage::new(Arc::clone(&pool), rec_idx);
    dmsg.set(md.field_by_name("exp_i32").unwrap(), Value::I32(-42));
    dmsg.set(md.field_by_name("exp_bool").unwrap(), Value::Bool(true));
    dmsg.set(md.field_by_name("exp_str").unwrap(), Value::String("hello".into()));
    dmsg.set(md.field_by_name("exp_bytes").unwrap(), Value::Bytes(vec![1, 2, 3]));
    dmsg.set(md.field_by_name("exp_f32").unwrap(), Value::F32(1.5));
    dmsg.set(md.field_by_name("exp_f64").unwrap(), Value::F64(-2.25));
    dmsg.set(md.field_by_name("exp_status").unwrap(), Value::EnumNumber(999));
    dmsg.set(md.field_by_name("imp_i32").unwrap(), Value::I32(55));
    dmsg.set(
        md.field_by_name("packed_nums").unwrap(),
        Value::List(vec![Value::I32(1), Value::I32(-2), Value::I32(3)]),
    );
    dmsg.set(
        md.field_by_name("expanded_nums").unwrap(),
        Value::List(vec![Value::I32(4), Value::I32(0), Value::I32(-5)]),
    );
    dmsg.set(
        md.field_by_name("scores").unwrap(),
        Value::Map(MapValue::from_entries(vec![
            (MapKey::String("alpha".into()), Value::I32(10)),
            (MapKey::String("zero".into()), Value::I32(0)),
        ])),
    );
    let mut c1 = DynamicMessage::new(Arc::clone(&pool), child_idx);
    c1.set(cmd.field_by_name("id").unwrap(), Value::I32(7));
    c1.set(cmd.field_by_name("label").unwrap(), Value::String("first".into()));
    dmsg.set(
        md.field_by_name("children").unwrap(),
        Value::Map(MapValue::from_entries(vec![(
            MapKey::String("c1".into()),
            Value::Message(c1),
        )])),
    );
    let mut cn = DynamicMessage::new(Arc::clone(&pool), child_idx);
    cn.set(cmd.field_by_name("id").unwrap(), Value::I32(0));
    cn.set(cmd.field_by_name("label").unwrap(), Value::String(String::new()));
    dmsg.set(md.field_by_name("nested").unwrap(), Value::Message(cn));
    let mut cd = DynamicMessage::new(Arc::clone(&pool), child_idx);
    cd.set(cmd.field_by_name("id").unwrap(), Value::I32(88));
    cd.set(cmd.field_by_name("label").unwrap(), Value::String("delim".into()));
    dmsg.set(md.field_by_name("delim_child").unwrap(), Value::Message(cd));
    let mut dl1 = DynamicMessage::new(Arc::clone(&pool), child_idx);
    dl1.set(cmd.field_by_name("id").unwrap(), Value::I32(10));
    dl1.set(cmd.field_by_name("label").unwrap(), Value::String("d1".into()));
    let mut dl2 = DynamicMessage::new(Arc::clone(&pool), child_idx);
    dl2.set(cmd.field_by_name("label").unwrap(), Value::String("d2".into()));
    dmsg.set(
        md.field_by_name("delim_list").unwrap(),
        Value::List(vec![Value::Message(dl1), Value::Message(dl2)]),
    );

    let buffa_wire = encode_buffa_dynamic(&dmsg, EncodeOptions::deterministic()).unwrap();
    assert_eq!(
        buffa_wire, wire_full,
        "Edition 2023 buffa_codec wire bytes must match Tier 1 generated code byte-for-byte"
    );
    let mut dmsg_rt = DynamicMessage::new(Arc::clone(&pool), rec_idx);
    decode_buffa_dynamic(&wire_full, &mut dmsg_rt).unwrap();
    assert_eq!(
        encode_buffa_dynamic(&dmsg_rt, EncodeOptions::deterministic()).unwrap(),
        wire_full
    );
}

fn test_edition_2024() {
    let mut counts = HashMap::new();
    counts.insert("k".to_owned(), 4);
    let rec = Record2024 {
        exp_num: Some(0),
        exp_flag: Some(false),
        imp_name: "svc-24".to_owned(),
        prio: Some(Priority::PriorityHigh as i32),
        delim_detail: Some(Detail2024 {
            code: Some(200),
            info: Some("ok".to_owned()),
        }),
        delim_details: vec![Detail2024 {
            code: Some(0),
            info: None,
        }],
        counts,
    };
    let wire = rec.marshal_omnibuf();
    assert_eq!(Record2024::from_omnibuf(&wire).unwrap(), rec);

    let mut op = OpaqueRecord2024::try_new(&wire).unwrap();
    assert!(op.has_exp_num());
    assert_eq!(op.get_exp_num(), 0);
    assert!(op.has_exp_flag());
    assert!(!op.get_exp_flag());
    assert_eq!(op.get_delim_detail().get_code(), 200);
    op.set_exp_num(None);
    op.set_exp_flag(Some(true));
    let spliced = op.try_marshal().unwrap();
    let rt = Record2024::from_omnibuf(&spliced).unwrap();
    assert_eq!(rt.exp_num, None);
    assert_eq!(rt.exp_flag, Some(true));

    let ch = Choice2024 {
        pick: Some(Choice2024Pick::ZeroOrNum(0)),
    };
    assert_eq!(Choice2024::from_omnibuf(&ch.marshal_omnibuf()).unwrap(), ch);

    // Cross-tier byte-for-byte wire equivalence with buffa_codec on Edition 2024 FDS.
    let pool = Arc::new(DescriptorPool::decode(include_bytes!("../desc/ed2024.pb")).unwrap());
    let rec_idx = pool.message_index("ed24.v1.Record2024").unwrap();
    let mut dyn_rt = DynamicMessage::new(Arc::clone(&pool), rec_idx);
    decode_buffa_dynamic(&wire, &mut dyn_rt).unwrap();
    let md = pool.message(rec_idx);
    assert!(dyn_rt.has(md.field_by_name("exp_num").unwrap()));
    assert!(dyn_rt.has(md.field_by_name("exp_flag").unwrap()));
    let buffa_wire = encode_buffa_dynamic(&dyn_rt, EncodeOptions::deterministic()).unwrap();
    assert_eq!(
        buffa_wire, wire,
        "Edition 2024 buffa_codec wire bytes must match Tier 1 generated code byte-for-byte"
    );
}

fn test_edition_2026() {
    let mut weights = HashMap::new();
    weights.insert("edge".to_owned(), 100);
    let mut metas = HashMap::new();
    metas.insert(
        "m1".to_owned(),
        Meta2026 {
            seq: Some(1),
            tag: Some("v26".to_owned()),
        },
    );
    let rec = Record2026 {
        exp_id: Some(0),
        exp_ok: Some(false),
        exp_msg: Some(String::new()),
        exp_raw: Some(Vec::new()),
        tier: Some(-7), // unknown open enum value preserved
        imp_counter: 9,
        packed_vals: vec![1, 2, 3],
        expanded_vals: vec![-1, 0, 1],
        weights,
        metas,
        delim_meta: Some(Meta2026 {
            seq: Some(26),
            tag: Some("delim26".to_owned()),
        }),
        delim_metas: vec![Meta2026 {
            seq: Some(0),
            tag: Some(String::new()),
        }],
    };
    let wire = rec.marshal_omnibuf();
    assert_eq!(Record2026::from_omnibuf(&wire).unwrap(), rec);

    let empty = Record2026::default();
    let empty_wire = empty.marshal_omnibuf();
    assert_ne!(empty_wire, wire);
    let op_empty = OpaqueRecord2026::try_new(&empty_wire).unwrap();
    assert!(!op_empty.has_exp_id());
    assert!(!op_empty.has_exp_ok());
    assert!(!op_empty.has_exp_msg());
    assert!(!op_empty.has_exp_raw());
    assert!(!op_empty.has_tier());

    let mut op = OpaqueRecord2026::try_new(&wire).unwrap();
    assert!(op.has_exp_id());
    assert_eq!(op.get_exp_id(), 0);
    assert!(op.has_exp_ok());
    assert!(!op.get_exp_ok());
    assert!(op.has_exp_msg());
    assert_eq!(op.get_exp_msg(), "");
    assert!(op.has_exp_raw());
    assert_eq!(op.get_exp_raw(), &[]);
    assert!(op.has_tier());
    assert_eq!(op.get_tier(), -7);
    assert_eq!(op.get_delim_meta().get_seq(), 26);
    op.set_tier(Some(Tier::TierCore as i32));
    op.set_exp_msg(None);
    let spliced = op.try_marshal().unwrap();
    let rt = Record2026::from_omnibuf(&spliced).unwrap();
    assert_eq!(rt.tier, Some(Tier::TierCore as i32));
    assert_eq!(rt.exp_msg, None);

    let ch = Choice2026 {
        tag: Some(2026),
        branch: Some(Choice2026Branch::Meta(Meta2026 {
            seq: Some(5),
            tag: Some("oneof26".to_owned()),
        })),
    };
    assert_eq!(Choice2026::from_omnibuf(&ch.marshal_omnibuf()).unwrap(), ch);

    // Cross-tier byte-for-byte wire equivalence with buffa_codec on real protoc 36.2 Edition 2026 FDS!
    let pool = Arc::new(DescriptorPool::decode(include_bytes!("../desc/ed2026.pb")).unwrap());
    let rec_idx = pool.message_index("ed26.v1.Record2026").unwrap();
    let mut dyn_rt = DynamicMessage::new(Arc::clone(&pool), rec_idx);
    decode_buffa_dynamic(&wire, &mut dyn_rt).unwrap();
    let buffa_wire = encode_buffa_dynamic(&dyn_rt, EncodeOptions::deterministic()).unwrap();
    assert_eq!(
        buffa_wire, wire,
        "Edition 2026 buffa_codec wire bytes must match Tier 1 generated code byte-for-byte"
    );
}

fn main() {
    test_edition_2023();
    test_edition_2024();
    test_edition_2026();
    println!("EDITIONS_E2E_OK");
}
"#,
    )
    .unwrap();

    let e2e_target_dir = workspace_root.join("target/editions-e2e-target");
    let run_out = Command::new("cargo")
        .arg("run")
        .arg("--offline")
        .arg("--manifest-path")
        .arg(tmp.path().join("Cargo.toml"))
        .env("CARGO_TARGET_DIR", &e2e_target_dir)
        .output()
        .expect("failed to invoke cargo run for E2E Editions verification");

    assert!(
        run_out.status.success(),
        "compiled E2E Editions runner failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run_out.stdout),
        String::from_utf8_lossy(&run_out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&run_out.stdout).contains("EDITIONS_E2E_OK"),
        "expected EDITIONS_E2E_OK marker"
    );
}
