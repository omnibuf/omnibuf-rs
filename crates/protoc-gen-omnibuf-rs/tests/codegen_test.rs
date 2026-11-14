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
