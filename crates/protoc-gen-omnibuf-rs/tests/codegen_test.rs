use prost_types::compiler::CodeGeneratorRequest;
use prost_types::field_descriptor_proto::{Label, Type};
use prost_types::{
    DescriptorProto, EnumDescriptorProto, EnumValueDescriptorProto, FieldDescriptorProto,
    FileDescriptorProto, MessageOptions,
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
    assert_eq!(file.name.as_deref(), Some("telemetry_omnibuf.rs"));

    let src = file.content.as_deref().unwrap();
    assert!(src.contains("pub enum LinkState"));
    assert!(!src.contains("LinkStateActive"));
    assert!(src.contains("pub struct PortReport"));
    assert!(src.contains("pub r#type: ::std::string::String"));
    assert!(src.contains("pub struct OpaquePortReport<'a>"));
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
