use prost_types::compiler::CodeGeneratorRequest;
use prost_types::descriptor_proto::ExtensionRange;
use prost_types::field_descriptor_proto::{Label, Type};
use prost_types::{
    DescriptorProto, EnumDescriptorProto, EnumValueDescriptorProto, FieldDescriptorProto,
    FileDescriptorProto, MessageOptions, OneofDescriptorProto,
};
use protoc_gen_omnibuf_rs::generate;

#[test]
fn generates_enums_nested_messages_maps_keywords_and_opaque_views() {
    let req = CodeGeneratorRequest {
        file_to_generate: vec!["net/telemetry.proto".to_owned()],
        parameter: None,
        compiler_version: None,
        proto_file: vec![FileDescriptorProto {
            name: Some("net/telemetry.proto".to_owned()),
            package: Some("net.v1".to_owned()),
            syntax: Some("proto3".to_owned()),
            enum_type: vec![EnumDescriptorProto {
                name: Some("LinkState".to_owned()),
                value: vec![
                    EnumValueDescriptorProto {
                        name: Some("LINK_STATE_DOWN".to_owned()),
                        number: Some(0),
                        options: None,
                    },
                    EnumValueDescriptorProto {
                        name: Some("LINK_STATE_UP".to_owned()),
                        number: Some(1),
                        options: None,
                    },
                    // Alias with duplicate discriminant 1 must be skipped cleanly in Rust repr(i32) enum.
                    EnumValueDescriptorProto {
                        name: Some("LINK_STATE_ACTIVE".to_owned()),
                        number: Some(1),
                        options: None,
                    },
                ],
                ..Default::default()
            }],
            message_type: vec![DescriptorProto {
                name: Some("PortReport".to_owned()),
                field: vec![
                    FieldDescriptorProto {
                        name: Some("type".to_owned()), // Rust keyword
                        number: Some(1),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::String as i32),
                        ..Default::default()
                    },
                    FieldDescriptorProto {
                        name: Some("state".to_owned()),
                        number: Some(2),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::Enum as i32),
                        type_name: Some(".net.v1.LinkState".to_owned()),
                        ..Default::default()
                    },
                    FieldDescriptorProto {
                        name: Some("counters".to_owned()),
                        number: Some(3),
                        label: Some(Label::Repeated as i32),
                        r#type: Some(Type::Message as i32),
                        type_name: Some(".net.v1.PortReport.CountersEntry".to_owned()),
                        ..Default::default()
                    },
                    FieldDescriptorProto {
                        name: Some("mtu".to_owned()),
                        number: Some(4),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::Uint32 as i32),
                        proto3_optional: Some(true),
                        ..Default::default()
                    },
                ],
                nested_type: vec![DescriptorProto {
                    name: Some("CountersEntry".to_owned()),
                    options: Some(MessageOptions {
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
                            r#type: Some(Type::Uint64 as i32),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };

    let resp = generate(&req);
    assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
    assert_eq!(resp.file.len(), 1);
    let file = &resp.file[0];
    assert_eq!(file.name.as_deref(), Some("net/telemetry_omnibuf.rs"));

    let src = file.content.as_deref().unwrap();
    assert!(src.contains("pub enum LinkState"));
    assert!(!src.contains("LinkStateActive"));
    assert!(src.contains("pub struct PortReport"));
    assert!(src.contains("pub r#type: ::std::string::String"));
    assert!(src.contains("pub struct OpaquePortReport<'a>"));
    assert!(src.contains("pub fn try_new(raw: &'a [u8]) -> ::omnibuf::Result<Self>"));
    assert!(src.contains("pub fn try_marshal(&self) -> ::omnibuf::Result<::std::vec::Vec<u8>>"));
    assert!(src.contains("pub fn lookup_counters(&self, key: &str)"));
    assert!(!src.contains("#![allow"));
}

#[test]
fn skips_opaque_view_when_field_number_exceeds_63_and_reports_invalid_field_number() {
    let high_field_req = CodeGeneratorRequest {
        file_to_generate: vec!["wide.proto".to_owned()],
        parameter: None,
        compiler_version: None,
        proto_file: vec![FileDescriptorProto {
            name: Some("wide.proto".to_owned()),
            package: Some("wide".to_owned()),
            syntax: Some("proto3".to_owned()),
            message_type: vec![DescriptorProto {
                name: Some("WideMsg".to_owned()),
                field: vec![FieldDescriptorProto {
                    name: Some("far_field".to_owned()),
                    number: Some(100),
                    label: Some(Label::Optional as i32),
                    r#type: Some(Type::Uint64 as i32),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    let resp = generate(&high_field_req);
    assert!(resp.error.is_none());
    let src = resp.file[0].content.as_deref().unwrap();
    assert!(src.contains("pub struct WideMsg"));
    assert!(!src.contains("OpaqueWideMsg"));

    // Negative field number returns a clean CodeGeneratorResponse.error instead of panicking.
    let bad_req = CodeGeneratorRequest {
        file_to_generate: vec!["bad.proto".to_owned()],
        parameter: None,
        compiler_version: None,
        proto_file: vec![FileDescriptorProto {
            name: Some("bad.proto".to_owned()),
            message_type: vec![DescriptorProto {
                name: Some("BadMsg".to_owned()),
                field: vec![FieldDescriptorProto {
                    name: Some("neg".to_owned()),
                    number: Some(-1),
                    label: Some(Label::Optional as i32),
                    r#type: Some(Type::Uint32 as i32),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    let bad_resp = generate(&bad_req);
    assert!(bad_resp.error.is_some());
}

#[test]
fn generates_oneofs_cross_file_imports_proto2_enum_defaults_and_rejects_groups_extensions() {
    // 1. Multi-file cross-package import + non-zero proto2 enum default + oneof + non-opaque child fallback + stem disambiguation.
    let req = CodeGeneratorRequest {
        file_to_generate: vec![
            "common/geo.proto".to_owned(),
            "edge/update.proto".to_owned(),
        ],
        parameter: None,
        compiler_version: None,
        proto_file: vec![
            FileDescriptorProto {
                name: Some("common/geo.proto".to_owned()),
                package: Some("common.v1".to_owned()),
                syntax: Some("proto2".to_owned()),
                enum_type: vec![EnumDescriptorProto {
                    name: Some("Priority".to_owned()),
                    value: vec![
                        EnumValueDescriptorProto {
                            name: Some("PRIORITY_HIGH".to_owned()),
                            number: Some(10),
                            options: None,
                        },
                        EnumValueDescriptorProto {
                            name: Some("PRIORITY_LOW".to_owned()),
                            number: Some(0),
                            options: None,
                        },
                    ],
                    ..Default::default()
                }],
                message_type: vec![DescriptorProto {
                    name: Some("DynamicAlert".to_owned()),
                    oneof_decl: vec![OneofDescriptorProto {
                        name: Some("detail".to_owned()),
                        options: None,
                    }],
                    field: vec![
                        FieldDescriptorProto {
                            name: Some("code".to_owned()),
                            number: Some(1),
                            label: Some(Label::Optional as i32),
                            r#type: Some(Type::Uint32 as i32),
                            oneof_index: Some(0),
                            ..Default::default()
                        },
                        FieldDescriptorProto {
                            name: Some("reason".to_owned()),
                            number: Some(2),
                            label: Some(Label::Optional as i32),
                            r#type: Some(Type::String as i32),
                            oneof_index: Some(0),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            },
            FileDescriptorProto {
                name: Some("edge/update.proto".to_owned()),
                package: Some("edge.v1".to_owned()),
                syntax: Some("proto3".to_owned()),
                dependency: vec!["common/geo.proto".to_owned()],
                message_type: vec![DescriptorProto {
                    name: Some("EdgePacket".to_owned()),
                    field: vec![
                        FieldDescriptorProto {
                            name: Some("prio".to_owned()),
                            number: Some(1),
                            label: Some(Label::Optional as i32),
                            r#type: Some(Type::Enum as i32),
                            type_name: Some(".common.v1.Priority".to_owned()),
                            ..Default::default()
                        },
                        // DynamicAlert has a oneof so OpaqueDynamicAlert is NOT generated;
                        // OpaqueEdgePacket must still be generated cleanly without referencing OpaqueDynamicAlert!
                        FieldDescriptorProto {
                            name: Some("alert".to_owned()),
                            number: Some(2),
                            label: Some(Label::Optional as i32),
                            r#type: Some(Type::Message as i32),
                            type_name: Some(".common.v1.DynamicAlert".to_owned()),
                            ..Default::default()
                        },
                        // Stem disambiguation: reserved stem `marshal` (#3) + snake_case collision `foo_bar` (#4) vs `FooBar` (#5)
                        FieldDescriptorProto {
                            name: Some("marshal".to_owned()),
                            number: Some(3),
                            label: Some(Label::Optional as i32),
                            r#type: Some(Type::Uint32 as i32),
                            proto3_optional: Some(true),
                            ..Default::default()
                        },
                        FieldDescriptorProto {
                            name: Some("foo_bar".to_owned()),
                            number: Some(4),
                            label: Some(Label::Optional as i32),
                            r#type: Some(Type::Bool as i32),
                            ..Default::default()
                        },
                        FieldDescriptorProto {
                            name: Some("FooBar".to_owned()),
                            number: Some(5),
                            label: Some(Label::Optional as i32),
                            r#type: Some(Type::Bool as i32),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            },
        ],
    };

    let resp = generate(&req);
    assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
    assert_eq!(resp.file.len(), 2);
    assert_eq!(resp.file[0].name.as_deref(), Some("common/geo_omnibuf.rs"));
    assert_eq!(resp.file[1].name.as_deref(), Some("edge/update_omnibuf.rs"));

    let geo_src = resp.file[0].content.as_deref().unwrap();
    // First declared enum variant (PriorityHigh = 10) gets #[default].
    assert!(geo_src.contains("#[default]\n    PriorityHigh = 10,"));
    assert!(geo_src.contains("pub enum DynamicAlertDetail"));
    assert!(geo_src.contains("pub detail: ::core::option::Option<DynamicAlertDetail>"));
    assert!(!geo_src.contains("OpaqueDynamicAlert"));

    let edge_src = resp.file[1].content.as_deref().unwrap();
    assert!(edge_src.contains("pub struct OpaqueEdgePacket<'a>"));
    assert!(!edge_src.contains("OpaqueDynamicAlert"));
    // Reserved stem `marshal` (#3) -> `marshal_3`, and colliding `foo_bar` (#4) + `FooBar` (#5) -> `foo_bar` + `foo_bar_5`.
    assert!(edge_src.contains("pub fn get_marshal_3("));
    assert!(edge_src.contains("pub fn get_foo_bar("));
    assert!(edge_src.contains("pub fn get_foo_bar_5("));

    // 2. Type::Group must return CodeGeneratorResponse.error per Spec §11.1.
    let group_req = CodeGeneratorRequest {
        file_to_generate: vec!["legacy_group.proto".to_owned()],
        parameter: None,
        compiler_version: None,
        proto_file: vec![FileDescriptorProto {
            name: Some("legacy_group.proto".to_owned()),
            syntax: Some("proto2".to_owned()),
            message_type: vec![DescriptorProto {
                name: Some("Outer".to_owned()),
                field: vec![FieldDescriptorProto {
                    name: Some("grp".to_owned()),
                    number: Some(1),
                    label: Some(Label::Optional as i32),
                    r#type: Some(Type::Group as i32),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    assert!(generate(&group_req).error.is_some());

    // 3. Proto2 extensions must return CodeGeneratorResponse.error per Spec §11.1.
    let ext_req = CodeGeneratorRequest {
        file_to_generate: vec!["legacy_ext.proto".to_owned()],
        parameter: None,
        compiler_version: None,
        proto_file: vec![FileDescriptorProto {
            name: Some("legacy_ext.proto".to_owned()),
            syntax: Some("proto2".to_owned()),
            message_type: vec![DescriptorProto {
                name: Some("Extendable".to_owned()),
                extension_range: vec![ExtensionRange {
                    start: Some(100),
                    end: Some(200),
                    options: None,
                }],
                ..Default::default()
            }],
            extension: vec![FieldDescriptorProto {
                name: Some("custom_ext".to_owned()),
                extendee: Some(".Extendable".to_owned()),
                number: Some(101),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Uint32 as i32),
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    assert!(generate(&ext_req).error.is_some());
}

/// Fields named `self`, `super`, `crate` must not emit illegal raw identifiers
/// (`r#self`, `r#super`, `r#crate`), which Rust rejects at the lexer/parser level.
#[test]
fn fields_self_super_crate_do_not_emit_illegal_raw_identifiers() {
    let req = CodeGeneratorRequest {
        file_to_generate: vec!["keywords.proto".to_owned()],
        parameter: None,
        compiler_version: None,
        proto_file: vec![FileDescriptorProto {
            name: Some("keywords.proto".to_owned()),
            package: Some("kw.v1".to_owned()),
            syntax: Some("proto3".to_owned()),
            message_type: vec![DescriptorProto {
                name: Some("PathKeywords".to_owned()),
                field: vec![
                    FieldDescriptorProto {
                        name: Some("self".to_owned()),
                        number: Some(1),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::String as i32),
                        ..Default::default()
                    },
                    FieldDescriptorProto {
                        name: Some("super".to_owned()),
                        number: Some(2),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::Uint32 as i32),
                        ..Default::default()
                    },
                    FieldDescriptorProto {
                        name: Some("crate".to_owned()),
                        number: Some(3),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::Bool as i32),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };

    let resp = generate(&req);
    assert!(
        resp.error.is_none(),
        "unexpected generator error: {:?}",
        resp.error
    );
    let src = resp.file[0].content.as_deref().unwrap();

    assert!(
        !src.contains("r#self") && !src.contains("r#super") && !src.contains("r#crate"),
        "generated Rust contains illegal raw identifier(s): r#self={}, r#super={}, r#crate={}",
        src.contains("r#self"),
        src.contains("r#super"),
        src.contains("r#crate"),
    );
}

/// Enum values `_0 = 0`, `FOO_BAR = 1`, `FooBar = 2` must neither emit a leading-digit
/// variant identifier (`0 = 0,`) nor emit duplicate `FooBar` variants in the same enum.
#[test]
fn enum_leading_digit_and_pascal_case_collision() {
    let req = CodeGeneratorRequest {
        file_to_generate: vec!["enums.proto".to_owned()],
        parameter: None,
        compiler_version: None,
        proto_file: vec![FileDescriptorProto {
            name: Some("enums.proto".to_owned()),
            package: Some("en.v1".to_owned()),
            syntax: Some("proto3".to_owned()),
            enum_type: vec![EnumDescriptorProto {
                name: Some("WeirdEnum".to_owned()),
                value: vec![
                    EnumValueDescriptorProto {
                        name: Some("_0".to_owned()),
                        number: Some(0),
                        options: None,
                    },
                    EnumValueDescriptorProto {
                        name: Some("FOO_BAR".to_owned()),
                        number: Some(1),
                        options: None,
                    },
                    EnumValueDescriptorProto {
                        name: Some("FooBar".to_owned()),
                        number: Some(2),
                        options: None,
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };

    let resp = generate(&req);
    assert!(
        resp.error.is_none(),
        "unexpected generator error: {:?}",
        resp.error
    );
    let src = resp.file[0].content.as_deref().unwrap();

    let enum_block = src
        .split("pub enum WeirdEnum {")
        .nth(1)
        .and_then(|rest| rest.split('}').next())
        .expect("missing WeirdEnum definition");

    let has_leading_digit_variant = enum_block.lines().any(|line| {
        let trimmed = line.trim();
        !trimmed.starts_with('#') && trimmed.chars().next().is_some_and(|ch| ch.is_ascii_digit())
    });
    assert!(
        !has_leading_digit_variant,
        "generated enum contains illegal leading-digit variant identifier:\n{enum_block}"
    );

    let foobar_count = enum_block
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            trimmed.starts_with("FooBar ") || trimmed.starts_with("FooBar=")
        })
        .count();
    assert!(
        foobar_count <= 1,
        "generated enum contains {foobar_count} colliding `FooBar` variants:\n{enum_block}"
    );
}

/// Cross-file imports of a hyphenated `.proto` filename (`my-service.proto`)
/// must sanitize `-` to `_` in generated Rust module paths instead of emitting `my-service_omnibuf`.
#[test]
fn hyphenated_proto_import_module_path_has_no_hyphens() {
    let req = CodeGeneratorRequest {
        file_to_generate: vec![
            "my-service.proto".to_owned(),
            "api/gateway.proto".to_owned(),
        ],
        parameter: None,
        compiler_version: None,
        proto_file: vec![
            FileDescriptorProto {
                name: Some("my-service.proto".to_owned()),
                package: Some("svc.v1".to_owned()),
                syntax: Some("proto3".to_owned()),
                message_type: vec![DescriptorProto {
                    name: Some("SvcConfig".to_owned()),
                    field: vec![FieldDescriptorProto {
                        name: Some("port".to_owned()),
                        number: Some(1),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::Uint32 as i32),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            },
            FileDescriptorProto {
                name: Some("api/gateway.proto".to_owned()),
                package: Some("api.v1".to_owned()),
                syntax: Some("proto3".to_owned()),
                dependency: vec!["my-service.proto".to_owned()],
                message_type: vec![DescriptorProto {
                    name: Some("Gateway".to_owned()),
                    field: vec![FieldDescriptorProto {
                        name: Some("cfg".to_owned()),
                        number: Some(1),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::Message as i32),
                        type_name: Some(".svc.v1.SvcConfig".to_owned()),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            },
        ],
    };

    let resp = generate(&req);
    assert!(
        resp.error.is_none(),
        "unexpected generator error: {:?}",
        resp.error
    );
    let gw_file = resp
        .file
        .iter()
        .find(|f| f.name.as_deref() == Some("api/gateway_omnibuf.rs"))
        .expect("missing api/gateway_omnibuf.rs");
    let gw_src = gw_file.content.as_deref().unwrap();

    assert!(
        !gw_src.contains("my-service_omnibuf"),
        "generated Rust module path contains illegal hyphenated identifier `my-service_omnibuf`"
    );
}

/// Flattening nested `message Foo { message Bar {} }` alongside top-level `message FooBar {}`
/// must disambiguate names rather than emitting two colliding `pub struct FooBar` definitions.
#[test]
fn nested_message_flattening_does_not_collide_with_top_level_message() {
    let req = CodeGeneratorRequest {
        file_to_generate: vec!["collide.proto".to_owned()],
        parameter: None,
        compiler_version: None,
        proto_file: vec![FileDescriptorProto {
            name: Some("collide.proto".to_owned()),
            package: Some("col.v1".to_owned()),
            syntax: Some("proto3".to_owned()),
            message_type: vec![
                DescriptorProto {
                    name: Some("Foo".to_owned()),
                    nested_type: vec![DescriptorProto {
                        name: Some("Bar".to_owned()),
                        field: vec![FieldDescriptorProto {
                            name: Some("nested_id".to_owned()),
                            number: Some(1),
                            label: Some(Label::Optional as i32),
                            r#type: Some(Type::Uint32 as i32),
                            ..Default::default()
                        }],
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                DescriptorProto {
                    name: Some("FooBar".to_owned()),
                    field: vec![FieldDescriptorProto {
                        name: Some("top_id".to_owned()),
                        number: Some(1),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::Uint32 as i32),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ],
            ..Default::default()
        }],
    };

    let resp = generate(&req);
    assert!(
        resp.error.is_none(),
        "unexpected generator error: {:?}",
        resp.error
    );
    let src = resp.file[0].content.as_deref().unwrap();

    let struct_defs = src.matches("pub struct FooBar ").count();
    assert!(
        struct_defs <= 1,
        "generated Rust defines `pub struct FooBar` {struct_defs} times in the same module"
    );
}

/// Generated `Opaque*::marshal_append` and `try_marshal_append` must append
/// to `dst` without calling `dst.clear()` or `copy_packet` / `try_copy_packet` (which wipe framing prefixes).
#[test]
fn opaque_marshal_append_preserves_dst_prefix() {
    let req = CodeGeneratorRequest {
        file_to_generate: vec!["frame.proto".to_owned()],
        parameter: None,
        compiler_version: None,
        proto_file: vec![FileDescriptorProto {
            name: Some("frame.proto".to_owned()),
            package: Some("frame.v1".to_owned()),
            syntax: Some("proto3".to_owned()),
            message_type: vec![DescriptorProto {
                name: Some("FramePacket".to_owned()),
                field: vec![FieldDescriptorProto {
                    name: Some("sequence".to_owned()),
                    number: Some(1),
                    label: Some(Label::Optional as i32),
                    r#type: Some(Type::Uint64 as i32),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };

    let resp = generate(&req);
    assert!(
        resp.error.is_none(),
        "unexpected generator error: {:?}",
        resp.error
    );
    let src = resp.file[0].content.as_deref().unwrap();

    let after_marshal_append = src
        .split("pub fn marshal_append(")
        .nth(1)
        .expect("missing OpaqueFramePacket::marshal_append");

    assert!(
        !after_marshal_append.contains("dst.clear()")
            && !after_marshal_append.contains("copy_packet(dst,")
            && !after_marshal_append.contains("try_copy_packet(dst,"),
        "generated marshal_append / try_marshal_append wipes existing `dst` framing prefix (clear={}, copy_packet={}, try_copy_packet={})",
        after_marshal_append.contains("dst.clear()"),
        after_marshal_append.contains("copy_packet(dst,"),
        after_marshal_append.contains("try_copy_packet(dst,"),
    );
}

/// Generated `Opaque` view for a message with `map<string, string> labels = 1;`,
/// `optional uint32 opt_port = 2;`, and `Sub sub = 3;` must expose `get_labels`,
/// `has_opt_port`, and `has_sub`.
#[test]
fn opaque_view_exposes_map_getter_and_presence_helpers() {
    let req = CodeGeneratorRequest {
        file_to_generate: vec!["service.proto".to_owned()],
        parameter: None,
        compiler_version: None,
        proto_file: vec![FileDescriptorProto {
            name: Some("service.proto".to_owned()),
            package: Some("svc.v1".to_owned()),
            syntax: Some("proto3".to_owned()),
            message_type: vec![
                DescriptorProto {
                    name: Some("Sub".to_owned()),
                    field: vec![FieldDescriptorProto {
                        name: Some("id".to_owned()),
                        number: Some(1),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::Uint32 as i32),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                DescriptorProto {
                    name: Some("ServiceCfg".to_owned()),
                    oneof_decl: vec![OneofDescriptorProto {
                        name: Some("_opt_port".to_owned()),
                        options: None,
                    }],
                    field: vec![
                        FieldDescriptorProto {
                            name: Some("labels".to_owned()),
                            number: Some(1),
                            label: Some(Label::Repeated as i32),
                            r#type: Some(Type::Message as i32),
                            type_name: Some(".svc.v1.ServiceCfg.LabelsEntry".to_owned()),
                            ..Default::default()
                        },
                        FieldDescriptorProto {
                            name: Some("opt_port".to_owned()),
                            number: Some(2),
                            label: Some(Label::Optional as i32),
                            r#type: Some(Type::Uint32 as i32),
                            oneof_index: Some(0),
                            proto3_optional: Some(true),
                            ..Default::default()
                        },
                        FieldDescriptorProto {
                            name: Some("sub".to_owned()),
                            number: Some(3),
                            label: Some(Label::Optional as i32),
                            r#type: Some(Type::Message as i32),
                            type_name: Some(".svc.v1.Sub".to_owned()),
                            ..Default::default()
                        },
                    ],
                    nested_type: vec![DescriptorProto {
                        name: Some("LabelsEntry".to_owned()),
                        options: Some(MessageOptions {
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
                                r#type: Some(Type::String as i32),
                                ..Default::default()
                            },
                        ],
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ],
            ..Default::default()
        }],
    };

    let resp = generate(&req);
    assert!(
        resp.error.is_none(),
        "unexpected generator error: {:?}",
        resp.error
    );
    let src = resp.file[0].content.as_deref().unwrap();

    assert!(src.contains("pub struct OpaqueServiceCfg<'a>"));
    assert!(
        src.contains("pub fn get_labels("),
        "OpaqueServiceCfg is missing `pub fn get_labels` for `map<string, string> labels`"
    );
    assert!(
        src.contains("pub fn has_opt_port("),
        "OpaqueServiceCfg is missing `pub fn has_opt_port` for `optional uint32 opt_port`"
    );
    assert!(
        src.contains("pub fn has_sub("),
        "OpaqueServiceCfg is missing `pub fn has_sub` for singular message field `Sub sub`"
    );
}

/// `protoc-gen-omnibuf-rs` must reject `syntax = "editions"` and proto2 non-zero
/// defaults, and preserve explicit presence (`Option<T>`) for proto2 optional scalar fields.
#[test]
fn proto2_explicit_presence_defaults_and_editions_rejection() {
    // 1. `syntax = "editions"` must return a clean error.
    let editions_req = CodeGeneratorRequest {
        file_to_generate: vec!["ed.proto".to_owned()],
        parameter: None,
        compiler_version: None,
        proto_file: vec![FileDescriptorProto {
            name: Some("ed.proto".to_owned()),
            syntax: Some("editions".to_owned()),
            message_type: vec![DescriptorProto {
                name: Some("EdMsg".to_owned()),
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
        }],
    };
    let ed_resp = generate(&editions_req);
    assert!(
        ed_resp.error.is_some(),
        "expected `syntax = \"editions\"` to be rejected"
    );

    // 2. Proto2 field with non-zero default must return a clean error.
    let nonzero_def_req = CodeGeneratorRequest {
        file_to_generate: vec!["p2_def.proto".to_owned()],
        parameter: None,
        compiler_version: None,
        proto_file: vec![FileDescriptorProto {
            name: Some("p2_def.proto".to_owned()),
            syntax: Some("proto2".to_owned()),
            message_type: vec![DescriptorProto {
                name: Some("DefMsg".to_owned()),
                field: vec![FieldDescriptorProto {
                    name: Some("retries".to_owned()),
                    number: Some(1),
                    label: Some(Label::Optional as i32),
                    r#type: Some(Type::Uint32 as i32),
                    default_value: Some("3".to_owned()),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    let def_resp = generate(&nonzero_def_req);
    assert!(
        def_resp.error.is_some(),
        "expected proto2 non-zero default_value to be rejected"
    );

    // 3. Proto2 optional scalar without non-zero default preserves explicit presence (`Option<T>`).
    let p2_opt_req = CodeGeneratorRequest {
        file_to_generate: vec!["p2_opt.proto".to_owned()],
        parameter: None,
        compiler_version: None,
        proto_file: vec![FileDescriptorProto {
            name: Some("p2_opt.proto".to_owned()),
            package: Some("p2.v1".to_owned()),
            syntax: Some("proto2".to_owned()),
            message_type: vec![DescriptorProto {
                name: Some("P2Config".to_owned()),
                field: vec![
                    FieldDescriptorProto {
                        name: Some("port".to_owned()),
                        number: Some(1),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::Uint32 as i32),
                        ..Default::default()
                    },
                    FieldDescriptorProto {
                        name: Some("enabled".to_owned()),
                        number: Some(2),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::Bool as i32),
                        default_value: Some("false".to_owned()),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    let p2_resp = generate(&p2_opt_req);
    assert!(
        p2_resp.error.is_none(),
        "unexpected error for proto2 optional scalars: {:?}",
        p2_resp.error
    );
    let src = p2_resp.file[0].content.as_deref().unwrap();
    assert!(
        src.contains("pub port: ::core::option::Option<u32>"),
        "expected proto2 optional uint32 to emit Option<u32>"
    );
    assert!(
        src.contains("pub enabled: ::core::option::Option<bool>"),
        "expected proto2 optional bool with zero default to emit Option<bool>"
    );
    assert!(
        src.contains("pub fn has_port("),
        "expected OpaqueP2Config to expose has_port for proto2 optional scalar"
    );
}

/// `tag_varint_width` must use Prefix-Varint thresholds (1/2/4/9), not LEB128 (1..5).
#[test]
fn tag_varint_width_uses_prefix_varint_thresholds() {
    let req = CodeGeneratorRequest {
        file_to_generate: vec!["tags.proto".to_owned()],
        parameter: None,
        compiler_version: None,
        proto_file: vec![FileDescriptorProto {
            name: Some("tags.proto".to_owned()),
            syntax: Some("proto3".to_owned()),
            message_type: vec![DescriptorProto {
                name: Some("WideTags".to_owned()),
                field: vec![
                    // tag = (2000 << 4) | 2 = 32002 -> Prefix-Varint width 4 (LEB128 was 3)
                    FieldDescriptorProto {
                        name: Some("mid_flag".to_owned()),
                        number: Some(2000),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::Bool as i32),
                        ..Default::default()
                    },
                    // tag = (50_000_000 << 4) | 2 = 800_000_002 -> Prefix-Varint width 9 (LEB128 was 5)
                    FieldDescriptorProto {
                        name: Some("high_flag".to_owned()),
                        number: Some(50_000_000),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::Bool as i32),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    let resp = generate(&req);
    assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
    let src = resp.file[0].content.as_deref().unwrap();
    let min_fn = src
        .split("fn min_wire_size_bounded(&self, depth_rem: usize) -> usize {")
        .nth(1)
        .and_then(|s| s.split("fn build_schema_meta").next())
        .expect("missing min_wire_size_bounded");
    assert!(
        min_fn.contains("4usize"),
        "expected 4-byte Prefix-Varint tag width for field #2000, got:\n{min_fn}"
    );
    assert!(
        min_fn.contains("9usize"),
        "expected 9-byte Prefix-Varint tag width for field #50_000_000, got:\n{min_fn}"
    );
}

/// Boxed oneof sub-messages must route through
/// `::omnibuf::codec::read_box_sub_msg_value` / `read_box_sub_msg_borrowed_value`
/// so `DecodeOptions::max_alloc_bytes` charges `size_of::<M>()`.
#[test]
fn boxed_oneof_uses_codec_box_helpers() {
    let req = CodeGeneratorRequest {
        file_to_generate: vec!["rec_oneof.proto".to_owned()],
        parameter: None,
        compiler_version: None,
        proto_file: vec![FileDescriptorProto {
            name: Some("rec_oneof.proto".to_owned()),
            package: Some("ro.v1".to_owned()),
            syntax: Some("proto3".to_owned()),
            message_type: vec![DescriptorProto {
                name: Some("Node".to_owned()),
                oneof_decl: vec![OneofDescriptorProto {
                    name: Some("next".to_owned()),
                    ..Default::default()
                }],
                field: vec![
                    FieldDescriptorProto {
                        name: Some("val".to_owned()),
                        number: Some(1),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::Uint32 as i32),
                        ..Default::default()
                    },
                    FieldDescriptorProto {
                        name: Some("child".to_owned()),
                        number: Some(2),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::Message as i32),
                        type_name: Some(".ro.v1.Node".to_owned()),
                        oneof_index: Some(0),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    let resp = generate(&req);
    assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
    let src = resp.file[0].content.as_deref().unwrap();
    assert!(
        src.contains("::omnibuf::codec::read_box_sub_msg_value::<Node>(__sb, depth + 1)?"),
        "expected owned boxed oneof to use read_box_sub_msg_value, got:\n{src}"
    );
    assert!(
        src.contains(
            "::omnibuf::codec::read_box_sub_msg_borrowed_value::<NodeBorrowed<'a>>(__sb, depth + 1)?"
        ),
        "expected borrowed boxed oneof to use read_box_sub_msg_borrowed_value, got:\n{src}"
    );
    assert!(
        !src.contains("Box::new("),
        "generated code should not bypass codec alloc charging with raw Box::new:\n{src}"
    );
}

/// Generated code avoids duplicating opaque dirty-field dispatch, Field #0 base schema maps,
/// leaf cyclic/value schema methods, and non-heap borrowed clear implementations.
#[test]
fn deduplicates_opaque_dispatch_schema_meta_and_borrowed_clear() {
    let req = CodeGeneratorRequest {
        file_to_generate: vec!["compact.proto".to_owned()],
        parameter: None,
        compiler_version: None,
        proto_file: vec![FileDescriptorProto {
            name: Some("compact.proto".to_owned()),
            package: Some("compact.v1".to_owned()),
            syntax: Some("proto3".to_owned()),
            message_type: vec![
                DescriptorProto {
                    name: Some("Vec3".to_owned()),
                    field: vec![
                        FieldDescriptorProto {
                            name: Some("x".to_owned()),
                            number: Some(1),
                            label: Some(Label::Optional as i32),
                            r#type: Some(Type::Float as i32),
                            ..Default::default()
                        },
                        FieldDescriptorProto {
                            name: Some("y".to_owned()),
                            number: Some(2),
                            label: Some(Label::Optional as i32),
                            r#type: Some(Type::Float as i32),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                },
                DescriptorProto {
                    name: Some("MeshNode".to_owned()),
                    field: vec![
                        FieldDescriptorProto {
                            name: Some("pos".to_owned()),
                            number: Some(1),
                            label: Some(Label::Optional as i32),
                            r#type: Some(Type::Message as i32),
                            type_name: Some(".compact.v1.Vec3".to_owned()),
                            ..Default::default()
                        },
                        FieldDescriptorProto {
                            name: Some("tags".to_owned()),
                            number: Some(2),
                            label: Some(Label::Repeated as i32),
                            r#type: Some(Type::String as i32),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                },
            ],
            ..Default::default()
        }],
    };
    let resp = generate(&req);
    assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
    let src = resp.file[0].content.as_deref().unwrap();

    // Opaque marshal_append and try_marshal_append share a single write_dirty_field helper per message.
    assert_eq!(src.matches("fn write_dirty_field(").count(), 2);
    assert_eq!(src.matches("self.write_dirty_field(dst, fnum)").count(), 4);

    // Leaf message (Vec3) omits is_schema_cyclic, build_value_schema_meta, and clear_omnibuf_borrowed.
    let (vec3_part, mesh_part) = src
        .split_once("pub struct MeshNode ")
        .expect("missing MeshNode");
    assert!(!vec3_part.contains("fn is_schema_cyclic("));
    assert!(!vec3_part.contains("fn build_value_schema_meta("));
    assert!(!vec3_part.contains("fn __omnibuf_base_schema_meta("));
    assert!(!vec3_part.contains("fn clear_omnibuf_borrowed("));
    assert!(vec3_part.contains("*self = ::core::default::Default::default();"));

    // Parent message (MeshNode) shares __omnibuf_base_schema_meta and keeps clear_omnibuf_borrowed for its Vec field.
    assert_eq!(
        mesh_part.matches("fn __omnibuf_base_schema_meta(").count(),
        1
    );
    assert_eq!(
        mesh_part
            .matches("Self::__omnibuf_base_schema_meta()")
            .count(),
        2
    );
    assert!(mesh_part.contains("fn is_schema_cyclic("));
    assert!(mesh_part.contains("fn build_value_schema_meta("));
    assert!(mesh_part.contains("fn clear_omnibuf_borrowed("));
}
