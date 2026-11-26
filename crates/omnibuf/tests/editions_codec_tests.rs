#![cfg(any(feature = "buffa", feature = "prost"))]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let id = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "omnibuf_codec_editions_{prefix}_{}_{id}",
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

fn compile_fds(files: &[(&str, &str)], targets: &[&str]) -> Vec<u8> {
    let tmp = TempDir::new("fds");
    for (name, content) in files {
        fs::write(tmp.path().join(name), content).unwrap();
    }
    let out_pb = tmp.path().join("out.pb");
    let mut cmd = Command::new("protoc");
    cmd.arg("-I")
        .arg(tmp.path())
        .arg("--include_imports")
        .arg("-o")
        .arg(&out_pb);
    for t in targets {
        cmd.arg(tmp.path().join(t));
    }
    let out = cmd.output().expect("failed to execute protoc");
    assert!(
        out.status.success(),
        "protoc failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    fs::read(out_pb).expect("read FileDescriptorSet bytes")
}

#[cfg(feature = "buffa")]
mod buffa_editions_tests {
    use std::sync::Arc;

    use buffa::Message as _;
    use buffa_descriptor::generated::descriptor::{
        DescriptorProto, Edition, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
        field_descriptor_proto::{Label, Type},
    };
    use buffa_descriptor::{
        DescriptorPool, DynamicMessage, MapKey, MapValue, ReflectMessage, ReflectMessageMut, Value,
        ValueRef,
    };
    use omnibuf::buffa_codec::{
        decode_buffa_dynamic, encode_buffa_dynamic, schema_meta_from_buffa_name,
    };
    use omnibuf::{EncodeOptions, decode_blind_json};

    use super::compile_fds;

    #[test]
    fn buffa_codec_supports_editions_2023_2024_and_2026_roundtrip_and_delimited() {
        let schemas: &[(&str, &str, &str)] = &[
            (
                "e2023.proto",
                "ed23.Rec",
                r#"edition = "2023";
package ed23;
enum Color {
  COLOR_UNSPECIFIED = 0;
  COLOR_BLUE = 1;
}
message Child {
  int32 x = 1 [default = 0];
}
message Rec {
  int32 exp_i32 = 1 [default = 0];
  bool exp_bool = 2 [default = false];
  string exp_str = 3 [default = ""];
  bytes exp_bytes = 4 [default = ""];
  Color exp_color = 5 [default = COLOR_UNSPECIFIED];
  int32 imp_i32 = 6 [features.field_presence = IMPLICIT];
  repeated int32 packed_arr = 7 [features.repeated_field_encoding = PACKED];
  repeated int32 expanded_arr = 8 [features.repeated_field_encoding = EXPANDED];
  map<string, int32> scores = 9;
  Child delim_child = 10 [features.message_encoding = DELIMITED];
  repeated Child delim_list = 11 [features.message_encoding = DELIMITED];
  oneof choice {
    int32 oneof_i32 = 12;
    bool oneof_bool = 13;
  }
}
"#,
            ),
            (
                "e2024.proto",
                "ed24.Rec",
                r#"edition = "2024";
package ed24;
option features.default_symbol_visibility = STRICT;
option features.enforce_naming_style = STYLE2024;
option features.json_format = LEGACY_BEST_EFFORT;
export enum Color {
  COLOR_UNSPECIFIED = 0;
  COLOR_BLUE = 1;
}
local message Child {
  int32 x = 1;
}
export message Rec {
  int32 exp_i32 = 1;
  bool exp_bool = 2;
  string exp_str = 3;
  bytes exp_bytes = 4;
  Color exp_color = 5;
  int32 imp_i32 = 6 [features.field_presence = IMPLICIT];
  repeated int32 packed_arr = 7 [features.repeated_field_encoding = PACKED];
  repeated int32 expanded_arr = 8 [features.repeated_field_encoding = EXPANDED];
  map<string, int32> scores = 9;
  Child delim_child = 10 [features.message_encoding = DELIMITED];
  repeated Child delim_list = 11 [features.message_encoding = DELIMITED];
  oneof choice {
    int32 oneof_i32 = 12;
    bool oneof_bool = 13;
  }
}
"#,
            ),
            (
                "e2026.proto",
                "ed26.Rec",
                r#"edition = "2026";
package ed26;
option features.enforce_naming_style = STYLE2026;
export enum Color {
  COLOR_UNSPECIFIED = 0;
  COLOR_BLUE = 1;
}
local message Child {
  option features.enforce_proto_limits = PROTO_LIMITS2026;
  int32 x = 1;
}
export message Rec {
  option features.enforce_proto_limits = PROTO_LIMITS2026;
  int32 exp_i32 = 1;
  bool exp_bool = 2;
  string exp_str = 3;
  bytes exp_bytes = 4;
  Color exp_color = 5;
  int32 imp_i32 = 6 [features.field_presence = IMPLICIT];
  repeated int32 packed_arr = 7 [features.repeated_field_encoding = PACKED];
  repeated int32 expanded_arr = 8 [features.repeated_field_encoding = EXPANDED];
  map<string, int32> scores = 9;
  Child delim_child = 10 [features.message_encoding = DELIMITED];
  repeated Child delim_list = 11 [features.message_encoding = DELIMITED];
  oneof choice {
    int32 oneof_i32 = 12;
    bool oneof_bool = 13;
  }
}
"#,
            ),
        ];

        for (file_name, rec_fqn, src) in schemas {
            let fds_bytes = compile_fds(&[(file_name, src)], &[file_name]);
            let pool = Arc::new(DescriptorPool::decode(&fds_bytes).unwrap());
            let rec_idx = pool.message_index(rec_fqn).unwrap();
            let child_fqn = rec_fqn.replace("Rec", "Child");
            let child_idx = pool.message_index(&child_fqn).unwrap();
            let md = pool.message(rec_idx);
            let cmd = pool.message(child_idx);

            // SchemaMeta includes delimited children in Editions.
            let meta = schema_meta_from_buffa_name(&pool, rec_fqn).unwrap();
            assert!(
                meta.children.contains_key(&10),
                "{file_name}: SchemaMeta must include delimited singular child #10"
            );
            assert!(
                meta.children.contains_key(&11),
                "{file_name}: SchemaMeta must include delimited repeated child #11"
            );

            // Absent vs explicit zeros/false/empty.
            let empty_msg = DynamicMessage::new(Arc::clone(&pool), rec_idx);
            let wire_empty =
                encode_buffa_dynamic(&empty_msg, EncodeOptions::deterministic()).unwrap();

            let mut zero_msg = DynamicMessage::new(Arc::clone(&pool), rec_idx);
            zero_msg.set(md.field_by_name("exp_i32").unwrap(), Value::I32(0));
            zero_msg.set(md.field_by_name("exp_bool").unwrap(), Value::Bool(false));
            zero_msg.set(
                md.field_by_name("exp_str").unwrap(),
                Value::String(String::new()),
            );
            zero_msg.set(
                md.field_by_name("exp_bytes").unwrap(),
                Value::Bytes(Vec::new()),
            );
            zero_msg.set(md.field_by_name("exp_color").unwrap(), Value::EnumNumber(0));
            zero_msg.set(md.field_by_name("oneof_bool").unwrap(), Value::Bool(false));
            let wire_zero =
                encode_buffa_dynamic(&zero_msg, EncodeOptions::deterministic()).unwrap();
            assert_ne!(
                wire_empty, wire_zero,
                "{file_name}: absent vs explicit zero must differ"
            );

            let mut zero_rt = DynamicMessage::new(Arc::clone(&pool), rec_idx);
            decode_buffa_dynamic(&wire_zero, &mut zero_rt).unwrap();
            assert!(zero_rt.has(md.field_by_name("exp_i32").unwrap()));
            assert!(zero_rt.has(md.field_by_name("exp_bool").unwrap()));
            assert!(zero_rt.has(md.field_by_name("exp_str").unwrap()));
            assert!(zero_rt.has(md.field_by_name("exp_bytes").unwrap()));
            assert!(zero_rt.has(md.field_by_name("exp_color").unwrap()));
            assert!(zero_rt.has(md.field_by_name("oneof_bool").unwrap()));
            assert!(!zero_rt.has(md.field_by_name("oneof_i32").unwrap()));

            // Populated message with unknown open enum, maps, packed/expanded, delimited singular & repeated.
            let mut full = DynamicMessage::new(Arc::clone(&pool), rec_idx);
            full.set(md.field_by_name("exp_i32").unwrap(), Value::I32(-9));
            full.set(
                md.field_by_name("exp_color").unwrap(),
                Value::EnumNumber(777),
            );
            full.set(md.field_by_name("imp_i32").unwrap(), Value::I32(12));
            full.set(
                md.field_by_name("packed_arr").unwrap(),
                Value::List(vec![Value::I32(1), Value::I32(2)]),
            );
            full.set(
                md.field_by_name("expanded_arr").unwrap(),
                Value::List(vec![Value::I32(3), Value::I32(4)]),
            );
            full.set(
                md.field_by_name("scores").unwrap(),
                Value::Map(MapValue::from_entries(vec![(
                    MapKey::String("k".into()),
                    Value::I32(99),
                )])),
            );
            let mut dc = DynamicMessage::new(Arc::clone(&pool), child_idx);
            dc.set(cmd.field_by_name("x").unwrap(), Value::I32(42));
            full.set(md.field_by_name("delim_child").unwrap(), Value::Message(dc));
            let mut dl = DynamicMessage::new(Arc::clone(&pool), child_idx);
            dl.set(cmd.field_by_name("x").unwrap(), Value::I32(55));
            full.set(
                md.field_by_name("delim_list").unwrap(),
                Value::List(vec![Value::Message(dl)]),
            );
            full.set(md.field_by_name("oneof_i32").unwrap(), Value::I32(0));

            let wire_sd = encode_buffa_dynamic(&full, EncodeOptions::self_describing()).unwrap();
            let json = decode_blind_json(&wire_sd).unwrap();
            assert!(
                json.contains("\"delim_child\":{\"x\":42}"),
                "{file_name}: {json}"
            );
            assert!(json.contains("\"exp_color\":777"), "{file_name}: {json}");

            let mut rt = DynamicMessage::new(Arc::clone(&pool), rec_idx);
            decode_buffa_dynamic(&wire_sd, &mut rt).unwrap();
            assert!(matches!(
                rt.get(md.field_by_name("exp_color").unwrap()),
                ValueRef::EnumNumber(777)
            ));
            assert!(rt.has(md.field_by_name("oneof_i32").unwrap()));
            let ValueRef::Message(sub) = rt.get(md.field_by_name("delim_child").unwrap()) else {
                panic!("{file_name}: expected delim_child message");
            };
            assert!(matches!(
                sub.get(cmd.field_by_name("x").unwrap()),
                ValueRef::I32(42)
            ));
        }
    }

    #[test]
    fn buffa_codec_rejects_unsupported_editions_and_disallowed_features() {
        // 1. Unsupported edition numbers: 0, 1003, 9999.
        let make_edition_pool = |raw_edition: i32| -> Arc<DescriptorPool> {
            let mut file = FileDescriptorProto {
                name: Some("bad_ed.proto".into()),
                package: Some("baded".into()),
                syntax: Some("editions".into()),
                message_type: vec![DescriptorProto {
                    name: Some("M".into()),
                    field: vec![FieldDescriptorProto {
                        name: Some("x".into()),
                        number: Some(1),
                        label: Some(Label::LABEL_OPTIONAL),
                        r#type: Some(Type::TYPE_INT32),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            };
            match raw_edition {
                0 => file.edition = Some(Edition::EDITION_UNKNOWN),
                9999 => file.edition = Some(Edition::EDITION_UNSTABLE),
                other => {
                    file.__buffa_unknown_fields.push(buffa::UnknownField {
                        number: 14,
                        data: buffa::UnknownFieldData::Varint(other as u64),
                    });
                }
            }
            let bytes = FileDescriptorSet {
                file: vec![file],
                ..Default::default()
            }
            .encode_to_vec();
            Arc::new(DescriptorPool::decode(&bytes).unwrap())
        };

        for unsupported in [0, 1003, 9999] {
            let pool = make_edition_pool(unsupported);
            let idx = pool.message_index("baded.M").unwrap();
            let mut msg = DynamicMessage::new(Arc::clone(&pool), idx);
            let enc_err = encode_buffa_dynamic(&msg, EncodeOptions::default())
                .unwrap_err()
                .to_string();
            assert!(
                enc_err.contains("unsupported protobuf edition"),
                "edition {unsupported} encode error: {enc_err}"
            );
            let dec_err = decode_buffa_dynamic(&[], &mut msg).unwrap_err().to_string();
            assert!(
                dec_err.contains("unsupported protobuf edition"),
                "edition {unsupported} decode error: {dec_err}"
            );
        }

        // 2. Real protoc negative Editions schemas rejected by buffa_codec (both encode and decode).
        type NegativeCodecCase<'a> = (&'a str, &'a [(&'a str, &'a str)], &'a str, &'a str, &'a str);
        let negative_cases: &[NegativeCodecCase<'_>] = &[
            (
                "closed_enum",
                &[(
                    "c.proto",
                    r#"edition = "2023";
package neg;
enum ClosedE {
  option features.enum_type = CLOSED;
  ZERO = 0;
}
message M { ClosedE e = 1; }
"#,
                )],
                "c.proto",
                "neg.M",
                "CLOSED",
            ),
            (
                "imported_proto2_closed_enum",
                &[
                    (
                        "p2.proto",
                        r#"syntax = "proto2";
package p2;
enum OldE { OLD_ZERO = 0; }
"#,
                    ),
                    (
                        "ed.proto",
                        r#"edition = "2026";
package neg;
import "p2.proto";
export message M { p2.OldE e = 1; }
"#,
                    ),
                ],
                "ed.proto",
                "neg.M",
                "CLOSED",
            ),
            (
                "legacy_required",
                &[(
                    "req.proto",
                    r#"edition = "2023";
package neg;
message M { int32 r = 1 [features.field_presence = LEGACY_REQUIRED]; }
"#,
                )],
                "req.proto",
                "neg.M",
                "LEGACY_REQUIRED",
            ),
            (
                "utf8_none_string",
                &[(
                    "u1.proto",
                    r#"edition = "2024";
package neg;
message M { string s = 1 [features.utf8_validation = NONE]; }
"#,
                )],
                "u1.proto",
                "neg.M",
                "utf8_validation",
            ),
            (
                "utf8_none_repeated_string",
                &[(
                    "u2.proto",
                    r#"edition = "2026";
package neg;
export message M { repeated string ss = 1 [features.utf8_validation = NONE]; }
"#,
                )],
                "u2.proto",
                "neg.M",
                "utf8_validation",
            ),
            (
                "utf8_none_map_key",
                &[(
                    "u3.proto",
                    r#"edition = "2023";
package neg;
message M { map<string, int32> m = 1 [features.utf8_validation = NONE]; }
"#,
                )],
                "u3.proto",
                "neg.M",
                "utf8_validation",
            ),
            (
                "utf8_none_map_value",
                &[(
                    "u4.proto",
                    r#"edition = "2026";
package neg;
option features.utf8_validation = NONE;
export message M { map<int32, string> m = 1; }
"#,
                )],
                "u4.proto",
                "neg.M",
                "utf8_validation",
            ),
            (
                "nonzero_default",
                &[(
                    "def.proto",
                    r#"edition = "2023";
package neg;
message M { int32 a = 1 [default = 7]; }
"#,
                )],
                "def.proto",
                "neg.M",
                "default",
            ),
            (
                "nonzero_enum_default",
                &[(
                    "defe.proto",
                    r#"edition = "2024";
package neg;
enum E { E_ZERO = 0; E_ONE = 1; }
message M { E e = 1 [default = E_ONE]; }
"#,
                )],
                "defe.proto",
                "neg.M",
                "default",
            ),
            (
                "non_option_extension",
                &[(
                    "ext.proto",
                    r#"edition = "2023";
package neg;
message M {
  int32 a = 1;
  extensions 100 to 200;
}
"#,
                )],
                "ext.proto",
                "neg.M",
                "extension",
            ),
        ];

        for (label, files, target, msg_fqn, expected) in negative_cases {
            let fds_bytes = compile_fds(files, &[target]);
            let pool = Arc::new(DescriptorPool::decode(&fds_bytes).unwrap());
            let idx = pool.message_index(msg_fqn).unwrap();
            let mut msg = DynamicMessage::new(Arc::clone(&pool), idx);
            let enc_err = encode_buffa_dynamic(&msg, EncodeOptions::default())
                .expect_err(label)
                .to_string();
            assert!(
                enc_err.contains(expected),
                "case {label} encode expected {expected:?}, got: {enc_err}"
            );
            let dec_err = decode_buffa_dynamic(&[], &mut msg)
                .expect_err(label)
                .to_string();
            assert!(
                dec_err.contains(expected),
                "case {label} decode expected {expected:?}, got: {dec_err}"
            );
        }
    }
}

#[cfg(feature = "prost")]
mod prost_editions_tests {
    use super::compile_fds;

    /// Documents exact `prost-reflect 0.16.5` behavior on real Editions 2023, 2024, and 2026
    /// `FileDescriptorSet`s produced by `protoc 36.2`: `prost-reflect` cannot parse
    /// `syntax = "editions"` (returning an error or panicking inside `Label::new` while building
    /// `DescriptorErrorKind::UnknownSyntax` before pushing the file to its pool).
    #[test]
    fn prost_reflect_rejects_editions_2023_2024_and_2026_descriptors() {
        let cases = [
            (
                "e2023.proto",
                r#"edition = "2023";
package p23;
message M { int32 a = 1; }
"#,
            ),
            (
                "e2024.proto",
                r#"edition = "2024";
package p24;
export message M { int32 a = 1; }
"#,
            ),
            (
                "e2026.proto",
                r#"edition = "2026";
package p26;
export message M { int32 a = 1; }
"#,
            ),
        ];

        for (name, src) in cases {
            let fds_bytes = compile_fds(&[(name, src)], &[name]);
            let outcome = std::panic::catch_unwind(|| {
                prost_reflect::DescriptorPool::decode(fds_bytes.as_slice())
            });
            match outcome {
                Ok(Ok(_)) => {
                    panic!("{name}: did not expect prost-reflect 0.16 to accept editions")
                }
                Ok(Err(err)) => {
                    let msg = err.to_string();
                    assert!(
                        msg.contains("editions"),
                        "{name}: expected editions syntax error from prost-reflect, got: {msg}"
                    );
                }
                Err(_) => {
                    // Upstream prost-reflect 0.16.5 bug: `NameVisitor::visit_file` calls
                    // `Label::new(&self.pool.files, ..., index, ...)` on `UnknownSyntax` before
                    // pushing the file at `index`, panicking with index out of bounds.
                }
            }
        }
    }
}
