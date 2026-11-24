#![cfg(feature = "derive")]

use std::collections::{BTreeMap, HashMap};

use omnibuf::wire::{
    Encoder, WIRE_ARRAY, WIRE_SINT, WIRE_STRING, WIRE_SUB_MSG, WIRE_UINT, append_tag,
    append_varint, encode_zigzag,
};
use omnibuf::{
    BlindValue, DecodeBlindOptions, DecodeOptions, EncodeOptions, Error, OmniBuf, SchemaMeta,
    decode_blind, decode_blind_json, decode_blind_with_options, decode_into,
    decode_into_with_options, from_slice, from_slice_with_options, stringify_blind_json, to_vec,
    to_vec_deterministic, to_vec_with_options,
};

#[derive(Clone, Debug, Default, PartialEq, OmniBuf)]
struct Point2D {
    #[omnibuf(id = 1)]
    x: u32,
    #[omnibuf(id = 2)]
    y: u32,
    #[omnibuf(id = 3)]
    label: String,
}

#[derive(Clone, Debug, Default, PartialEq, OmniBuf)]
#[omnibuf(name = "TreeNode")]
struct TreeNode {
    #[omnibuf(id = 1, name = "value", wire = "sint")]
    value: i64,
    #[omnibuf(id = 2, name = "label", omitempty)]
    label: String,
    #[omnibuf(id = 3, name = "left")]
    left: Option<Box<TreeNode>>,
    #[omnibuf(id = 4, name = "children")]
    children: Vec<TreeNode>,
}

#[derive(Clone, Debug, Default, PartialEq, OmniBuf)]
#[omnibuf(name = "WireOverrides")]
struct WireOverrides {
    #[omnibuf(id = 1, wire = "fixed32", omitempty)]
    f32_id: u32,
    #[omnibuf(id = 2, wire = "fixed64")]
    f64_id: u64,
    #[omnibuf(id = 3, wire = "sfixed32")]
    sf32_delta: i32,
    #[omnibuf(id = 4, wire = "sfixed64")]
    sf64_delta: i64,
    #[omnibuf(id = 5)]
    opt_flag: Option<bool>,
    #[omnibuf(id = 6)]
    metrics: HashMap<String, u64>,
    #[omnibuf(id = 7)]
    ordered_nodes: BTreeMap<i32, Point2D>,
    #[omnibuf(skip)]
    transient_cache: usize,
}

#[test]
fn derive_recursive_self_describing_and_reuse_semantics() {
    let p = Point2D {
        x: 10,
        y: 20,
        label: "origin".to_owned(),
    };
    let bytes = to_vec(&p).unwrap();
    let decoded: Point2D = from_slice(&bytes).unwrap();
    assert_eq!(decoded, p);

    let tree = TreeNode {
        value: -42,
        label: String::new(), // omitempty skips wire emission
        left: Some(Box::new(TreeNode {
            value: 7,
            label: "left-leaf".to_owned(),
            left: None,
            children: Vec::new(),
        })),
        children: vec![
            TreeNode {
                value: 100,
                label: "c1".to_owned(),
                left: None,
                children: Vec::new(),
            },
            TreeNode {
                value: -200,
                label: "c2".to_owned(),
                left: None,
                children: Vec::new(),
            },
        ],
    };

    let packet = to_vec_with_options(&tree, EncodeOptions::self_describing()).unwrap();
    let roundtrip: TreeNode = from_slice(&packet).unwrap();
    assert_eq!(roundtrip, tree);

    // Blind JSON inspection resolves self-describing Field #0 names recursively.
    let json = decode_blind_json(&packet).unwrap();
    assert!(json.contains("\"value\":-42"));
    assert!(json.contains("\"left-leaf\""));
    assert!(json.contains("\"children\""));

    // Reuse of a dirty struct resets unseen fields on decode_into.
    let empty_tree = TreeNode::default();
    let empty_bytes = to_vec(&empty_tree).unwrap();
    let mut reused = tree.clone();
    decode_into(&empty_bytes, &mut reused).unwrap();
    assert_eq!(reused, empty_tree);
}

#[test]
fn derive_wire_overrides_and_deterministic_maps() {
    let mut metrics = HashMap::new();
    metrics.insert("z_key".to_owned(), 3);
    metrics.insert("a_key".to_owned(), 1);
    metrics.insert("m_key".to_owned(), 2);

    let mut ordered_nodes = BTreeMap::new();
    ordered_nodes.insert(
        -5,
        Point2D {
            x: 1,
            y: 2,
            label: "neg".to_owned(),
        },
    );

    let msg = WireOverrides {
        f32_id: 0, // omitempty
        f64_id: 0xCAFE_BABE_1234_5678,
        sf32_delta: -77,
        sf64_delta: -999_999_999_999,
        opt_flag: Some(false),
        metrics,
        ordered_nodes,
        transient_cache: 999,
    };

    let b1 = to_vec_deterministic(&msg).unwrap();
    let b2 = to_vec_deterministic(&msg).unwrap();
    assert_eq!(b1, b2, "deterministic map encoding must be byte-identical");

    let mut out = WireOverrides {
        transient_cache: 123,
        ..Default::default()
    };
    decode_into(&b1, &mut out).unwrap();
    assert_eq!(out.f64_id, msg.f64_id);
    assert_eq!(out.sf32_delta, msg.sf32_delta);
    assert_eq!(out.sf64_delta, msg.sf64_delta);
    assert_eq!(out.opt_flag, Some(false));
    assert_eq!(out.metrics, msg.metrics);
    assert_eq!(out.ordered_nodes, msg.ordered_nodes);
    // Skipped fields are untouched by OmniBuf encode/decode.
    assert_eq!(out.transient_cache, 123);
}

#[test]
fn blind_decoder_64bit_precision_f32_shortest_and_trailing_field0() {
    let mut enc = Encoder::default();
    enc.write_uint(1, u64::MAX);
    enc.write_sint(2, i64::MIN);
    enc.write_float32(3, 50.1109_f32);
    enc.write_bytes(4, b"hello");

    // Append a trailing Field #0 block renaming fields 1..4 after payload emission.
    let mut meta = SchemaMeta {
        type_name: "DynamicPacket".to_owned(),
        ..Default::default()
    };
    meta.fields.insert(1, "max_u64".to_owned());
    meta.fields.insert(2, "min_i64".to_owned());
    meta.fields.insert(3, "lat_f32".to_owned());
    meta.fields.insert(4, "raw_payload".to_owned());
    let mut packet = enc.into_vec();
    meta.append_field0(&mut packet).unwrap();

    let map = decode_blind(&packet).unwrap();
    assert_eq!(map.get("max_u64"), Some(&BlindValue::Uint(u64::MAX)));
    assert_eq!(map.get("min_i64"), Some(&BlindValue::Int(i64::MIN)));

    let json = decode_blind_json(&packet).unwrap();
    assert!(json.contains("\"max_u64\":18446744073709551615"));
    assert!(json.contains("\"min_i64\":-9223372036854775808"));
    assert!(json.contains("\"lat_f32\":50.1109"));
    assert!(json.contains("\"raw_payload\":\"aGVsbG8=\""));
    assert_eq!(stringify_blind_json(&map, None, true), json);

    // Non-finite floats return Err(Error::Serialize) from decode_blind_json,
    // while stringify_blind_json(..., fallback_on_non_finite = true) returns "{}".
    for non_finite in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let mut nf_enc = Encoder::default();
        nf_enc.write_float64(1, non_finite);
        let nf_pkt = nf_enc.into_vec();
        let nf_map = decode_blind(&nf_pkt).unwrap();
        assert!(matches!(
            decode_blind_json(&nf_pkt),
            Err(Error::Serialize(_))
        ));
        assert_eq!(stringify_blind_json(&nf_map, None, true), "{}");
    }

    // Negative zero (-0.0) is preserved as "-0.0" in decode_blind_json.
    let mut nz_enc = Encoder::default();
    nz_enc.write_float32(1, -0.0_f32);
    nz_enc.write_float64(2, -0.0_f64);
    let nz_json = decode_blind_json(&nz_enc.into_vec()).unwrap();
    assert_eq!(nz_json, "{\"field_1\":-0.0,\"field_2\":-0.0}");
}

#[test]
fn blind_decoder_rejects_name_collision_and_wire_shape_conflict() {
    // 1. Two distinct field numbers mapped to the same name in Field #0 must error.
    let mut meta = SchemaMeta::default();
    meta.fields.insert(1, "dup_name".to_owned());
    meta.fields.insert(2, "dup_name".to_owned());
    let mut pkt = Vec::new();
    meta.append_field0(&mut pkt).unwrap();
    append_tag(&mut pkt, 1, WIRE_UINT);
    append_varint(&mut pkt, 1);
    append_tag(&mut pkt, 2, WIRE_UINT);
    append_varint(&mut pkt, 2);
    assert!(decode_blind(&pkt).is_err());

    // 2. Same field number changing from scalar to sub-message must error.
    let mut shape_conflict = Vec::new();
    append_tag(&mut shape_conflict, 1, WIRE_STRING);
    append_varint(&mut shape_conflict, 2);
    shape_conflict.extend_from_slice(b"hi");
    append_tag(&mut shape_conflict, 1, WIRE_SUB_MSG);
    append_varint(&mut shape_conflict, 0);
    assert!(decode_blind(&shape_conflict).is_err());

    // 3. Split corrupt sub-message halves ([0x21, 0x02] + [0x00]) must be rejected individually.
    let mut split_corrupt = Vec::new();
    append_tag(&mut split_corrupt, 8, WIRE_SUB_MSG);
    append_varint(&mut split_corrupt, 2);
    split_corrupt.extend_from_slice(&[0x21, 0x02]);
    append_tag(&mut split_corrupt, 8, WIRE_SUB_MSG);
    append_varint(&mut split_corrupt, 1);
    split_corrupt.push(0x00);
    assert!(decode_blind(&split_corrupt).is_err());

    // 4. Nested WireArray(WireArray(WireUint)) followed by WireArray(WireArray(WireString)) must error.
    let mut nested_arr_conflict = Vec::new();
    // Occurrence 1: WireArray(elem=WireArray, count=1) -> inner WireArray(elem=WireUint, count=1, val=7)
    let mut inner_uint = Vec::new();
    inner_uint.push(WIRE_UINT);
    append_varint(&mut inner_uint, 1);
    append_varint(&mut inner_uint, 7);
    let mut outer1 = Vec::new();
    outer1.push(WIRE_ARRAY);
    append_varint(&mut outer1, 1);
    append_varint(&mut outer1, inner_uint.len() as u64);
    outer1.extend_from_slice(&inner_uint);
    append_tag(&mut nested_arr_conflict, 99, WIRE_ARRAY);
    append_varint(&mut nested_arr_conflict, outer1.len() as u64);
    nested_arr_conflict.extend_from_slice(&outer1);

    // Occurrence 2: WireArray(elem=WireArray, count=1) -> inner WireArray(elem=WireString, count=1, val="x")
    let mut inner_str = Vec::new();
    inner_str.push(WIRE_STRING);
    append_varint(&mut inner_str, 1);
    append_varint(&mut inner_str, 1);
    inner_str.push(b'x');
    let mut outer2 = Vec::new();
    outer2.push(WIRE_ARRAY);
    append_varint(&mut outer2, 1);
    append_varint(&mut outer2, inner_str.len() as u64);
    outer2.extend_from_slice(&inner_str);
    append_tag(&mut nested_arr_conflict, 99, WIRE_ARRAY);
    append_varint(&mut nested_arr_conflict, outer2.len() as u64);
    nested_arr_conflict.extend_from_slice(&outer2);
    assert!(decode_blind(&nested_arr_conflict).is_err());
}

#[derive(Clone, Debug, PartialEq, OmniBuf)]
enum ControlPayload {
    #[omnibuf(id = 10, name = "ping_seq")]
    PingSeq(u64),
    #[omnibuf(id = 11, name = "target_point")]
    TargetPoint(Point2D),
    #[omnibuf(id = 12, name = "boxed_tree")]
    BoxedTree(Box<TreeNode>),
}

#[derive(Clone, Debug, Default, PartialEq, OmniBuf)]
#[omnibuf(name = "ControlEnvelope")]
struct ControlEnvelope {
    #[prost(uint32, tag = "1")]
    #[omnibuf(name = "envelope_id")]
    id: u32,
    #[omnibuf(id = 2)]
    narrow_u8: u8,
    #[omnibuf(id = 3)]
    narrow_i16: i16,
    #[omnibuf(id = 4)]
    matrix: Vec<Vec<i32>>,
    #[omnibuf(id = 5)]
    buckets: HashMap<String, Vec<u32>>,
    #[omnibuf(id = 6)]
    point_groups: BTreeMap<i32, Vec<Point2D>>,
    #[prost(oneof = "ControlPayload", tags = "10, 11, 12")]
    payload: Option<ControlPayload>,
}

#[test]
fn derive_oneof_layered_attrs_narrow_ints_nested_containers_and_decode_options() {
    let mut buckets = HashMap::new();
    buckets.insert("ingress".to_owned(), vec![10, 20, 30]);
    let mut point_groups = BTreeMap::new();
    point_groups.insert(
        1,
        vec![Point2D {
            x: 3,
            y: 4,
            label: "p1".to_owned(),
        }],
    );

    let env = ControlEnvelope {
        id: 77,
        narrow_u8: 250,
        narrow_i16: -30_000,
        matrix: vec![vec![1, -2, 3], vec![], vec![42]],
        buckets,
        point_groups,
        payload: Some(ControlPayload::TargetPoint(Point2D {
            x: 9,
            y: 8,
            label: "oneof-pt".to_owned(),
        })),
    };

    let wire = to_vec_with_options(&env, EncodeOptions::self_describing()).unwrap();
    let rt: ControlEnvelope = from_slice(&wire).unwrap();
    assert_eq!(rt, env);

    // Self-describing Field #0 includes layered `envelope_id`, oneof arm `target_point`, and nested Point2D names.
    let blind_json = decode_blind_json(&wire).unwrap();
    assert!(blind_json.contains("\"envelope_id\":77"));
    assert!(blind_json.contains("\"target_point\""));
    assert!(blind_json.contains("\"oneof-pt\""));

    // Concatenating a later oneof arm replaces the previous arm ("last oneof arm wins").
    let env2 = ControlEnvelope {
        payload: Some(ControlPayload::PingSeq(999)),
        ..Default::default()
    };
    let mut merged = wire.clone();
    merged.extend_from_slice(&to_vec(&env2).unwrap());
    let merged_rt: ControlEnvelope = from_slice(&merged).unwrap();
    assert_eq!(merged_rt.payload, Some(ControlPayload::PingSeq(999)));

    // Narrow integer overflow (u8 > 255 and i16 < -32768) returns a clean parse Error instead of truncating.
    let mut u8_overflow = Vec::new();
    append_tag(&mut u8_overflow, 2, WIRE_UINT);
    append_varint(&mut u8_overflow, 256);
    assert!(from_slice::<ControlEnvelope>(&u8_overflow).is_err());

    let mut i16_overflow = Vec::new();
    append_tag(&mut i16_overflow, 3, WIRE_SINT);
    append_varint(&mut i16_overflow, encode_zigzag(-40_000));
    assert!(from_slice::<ControlEnvelope>(&i16_overflow).is_err());

    // DecodeOptions & DecodeBlindOptions enforce max_message_bytes, max_elements, max_alloc_bytes, and max_depth.
    assert!(
        from_slice_with_options::<ControlEnvelope>(
            &wire,
            DecodeOptions {
                max_message_bytes: 8,
                ..DecodeOptions::default()
            },
        )
        .is_err()
    );
    let mut tmp = ControlEnvelope::default();
    assert!(
        decode_into_with_options(
            &wire,
            &mut tmp,
            DecodeOptions {
                max_elements: 2,
                ..DecodeOptions::default()
            },
        )
        .is_err()
    );
    assert!(
        decode_blind_with_options(
            &wire,
            DecodeBlindOptions {
                max_alloc_bytes: 16,
                ..DecodeBlindOptions::default()
            },
        )
        .is_err()
    );
    assert!(matches!(
        decode_blind_with_options(
            &wire,
            DecodeBlindOptions {
                max_depth: 1,
                ..DecodeBlindOptions::default()
            },
        ),
        Err(Error::DepthLimitExceeded(_))
    ));
}

#[test]
fn six_level_recursive_tree_self_describing_preserves_all_nested_field_names() {
    let mut cur = TreeNode {
        value: 6,
        label: "level-6-leaf".to_owned(),
        left: None,
        children: Vec::new(),
    };
    for lvl in (1..=5).rev() {
        cur = TreeNode {
            value: lvl,
            label: format!("level-{lvl}-node"),
            left: Some(Box::new(cur)),
            children: Vec::new(),
        };
    }

    let pkt = to_vec_with_options(&cur, EncodeOptions::self_describing()).unwrap();
    let json = decode_blind_json(&pkt).unwrap();
    for lvl in 1..=5 {
        assert!(
            json.contains(&format!("\"level-{lvl}-node\"")),
            "missing level-{lvl}-node in {json}"
        );
    }
    assert!(
        json.contains("\"label\":\"level-6-leaf\""),
        "expected depth-6 recursive field name `label` to be preserved, got {json}"
    );
}

#[cfg(feature = "prost")]
#[test]
fn prost_codec_dynamic_roundtrip_and_neg_zero_preservation() {
    use omnibuf::prost_codec::{decode_dynamic, encode_dynamic, schema_meta_from_descriptor};
    use prost_reflect::prost_types::{
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
        field_descriptor_proto::{Label, Type},
    };
    use prost_reflect::{DescriptorPool, DynamicMessage, Value as ReflectValue};

    let fds = FileDescriptorSet {
        file: vec![FileDescriptorProto {
            name: Some("test_dyn.proto".to_owned()),
            package: Some("dynpkg".to_owned()),
            syntax: Some("proto3".to_owned()),
            message_type: vec![DescriptorProto {
                name: Some("SensorSample".to_owned()),
                field: vec![
                    FieldDescriptorProto {
                        name: Some("temp_c".to_owned()),
                        number: Some(1),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::Float as i32),
                        ..Default::default()
                    },
                    FieldDescriptorProto {
                        name: Some("pressure_kpa".to_owned()),
                        number: Some(2),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::Double as i32),
                        ..Default::default()
                    },
                    FieldDescriptorProto {
                        name: Some("sensor_id".to_owned()),
                        number: Some(3),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::String as i32),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };

    let pool = DescriptorPool::from_file_descriptor_set(fds).unwrap();
    let desc = pool.get_message_by_name("dynpkg.SensorSample").unwrap();

    let meta = schema_meta_from_descriptor(&desc);
    assert_eq!(meta.type_name, "SensorSample");
    assert_eq!(meta.fields.get(&1).map(String::as_str), Some("temp_c"));

    let mut dyn_msg = DynamicMessage::new(desc.clone());
    dyn_msg.set_field_by_name("temp_c", ReflectValue::F32(-0.0_f32));
    dyn_msg.set_field_by_name("pressure_kpa", ReflectValue::F64(-0.0_f64));
    dyn_msg.set_field_by_name("sensor_id", ReflectValue::String("fra-01".to_owned()));

    let encoded = encode_dynamic(&dyn_msg, EncodeOptions::self_describing()).unwrap();
    let mut decoded = DynamicMessage::new(desc.clone());
    decode_dynamic(&encoded, &mut decoded).unwrap();
    let f32_bits = decoded
        .get_field_by_name("temp_c")
        .unwrap()
        .as_f32()
        .unwrap()
        .to_bits();
    let f64_bits = decoded
        .get_field_by_name("pressure_kpa")
        .unwrap()
        .as_f64()
        .unwrap()
        .to_bits();
    assert_eq!(f32_bits, (-0.0_f32).to_bits());
    assert_eq!(f64_bits, (-0.0_f64).to_bits());
    assert_eq!(
        decoded.get_field_by_name("sensor_id").unwrap().as_str(),
        Some("fra-01")
    );
}

#[cfg(feature = "prost")]
#[test]
fn prost_codec_preserves_neg_zero_in_repeated_and_map_submessages_and_rejects_groups_extensions() {
    use std::collections::HashMap as StdHashMap;

    use omnibuf::prost_codec::{decode_dynamic, decode_dynamic_with_options, encode_dynamic};
    use prost_reflect::prost_types::{
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
        MessageOptions,
        descriptor_proto::ExtensionRange,
        field_descriptor_proto::{Label, Type},
    };
    use prost_reflect::{DescriptorPool, DynamicMessage, MapKey, Value as ReflectValue};

    let fds = FileDescriptorSet {
        file: vec![FileDescriptorProto {
            name: Some("test_ext.proto".to_owned()),
            package: Some("extpkg".to_owned()),
            syntax: Some("proto2".to_owned()),
            message_type: vec![
                DescriptorProto {
                    name: Some("Reading".to_owned()),
                    field: vec![FieldDescriptorProto {
                        name: Some("val".to_owned()),
                        number: Some(1),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::Float as i32),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                DescriptorProto {
                    name: Some("Batch".to_owned()),
                    field: vec![
                        FieldDescriptorProto {
                            name: Some("items".to_owned()),
                            number: Some(1),
                            label: Some(Label::Repeated as i32),
                            r#type: Some(Type::Message as i32),
                            type_name: Some(".extpkg.Reading".to_owned()),
                            ..Default::default()
                        },
                        FieldDescriptorProto {
                            name: Some("by_key".to_owned()),
                            number: Some(2),
                            label: Some(Label::Repeated as i32),
                            r#type: Some(Type::Message as i32),
                            type_name: Some(".extpkg.Batch.ByKeyEntry".to_owned()),
                            ..Default::default()
                        },
                    ],
                    nested_type: vec![DescriptorProto {
                        name: Some("ByKeyEntry".to_owned()),
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
                                r#type: Some(Type::Message as i32),
                                type_name: Some(".extpkg.Reading".to_owned()),
                                ..Default::default()
                            },
                        ],
                        ..Default::default()
                    }],
                    extension_range: vec![ExtensionRange {
                        start: Some(100),
                        end: Some(200),
                        options: None,
                    }],
                    ..Default::default()
                },
                DescriptorProto {
                    name: Some("GroupHolder".to_owned()),
                    field: vec![FieldDescriptorProto {
                        name: Some("legacygroup".to_owned()),
                        number: Some(1),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::Group as i32),
                        type_name: Some(".extpkg.GroupHolder.LegacyGroup".to_owned()),
                        ..Default::default()
                    }],
                    nested_type: vec![DescriptorProto {
                        name: Some("LegacyGroup".to_owned()),
                        field: vec![FieldDescriptorProto {
                            name: Some("x".to_owned()),
                            number: Some(2),
                            label: Some(Label::Optional as i32),
                            r#type: Some(Type::Uint32 as i32),
                            ..Default::default()
                        }],
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ],
            extension: vec![FieldDescriptorProto {
                name: Some("ext_tag".to_owned()),
                extendee: Some(".extpkg.Batch".to_owned()),
                number: Some(105),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Uint32 as i32),
                ..Default::default()
            }],
            ..Default::default()
        }],
    };

    let pool = DescriptorPool::from_file_descriptor_set(fds).unwrap();
    let reading_desc = pool.get_message_by_name("extpkg.Reading").unwrap();
    let batch_desc = pool.get_message_by_name("extpkg.Batch").unwrap();
    let group_desc = pool.get_message_by_name("extpkg.GroupHolder").unwrap();
    let ext_fd = pool.get_extension_by_name("extpkg.ext_tag").unwrap();

    // 1. -0.0 inside repeated SubMsg and map<string, SubMsg> is preserved across OmniBuf encode/decode.
    let mut r_neg = DynamicMessage::new(reading_desc);
    r_neg.set_field_by_name("val", ReflectValue::F32(-0.0_f32));
    let mut map_entries = StdHashMap::new();
    map_entries.insert(
        MapKey::String("k0".to_owned()),
        ReflectValue::Message(r_neg.clone()),
    );

    let mut batch = DynamicMessage::new(batch_desc.clone());
    batch.set_field_by_name(
        "items",
        ReflectValue::List(vec![ReflectValue::Message(r_neg)]),
    );
    batch.set_field_by_name("by_key", ReflectValue::Map(map_entries));

    let wire = encode_dynamic(&batch, EncodeOptions::deterministic()).unwrap();
    let mut rt = DynamicMessage::new(batch_desc.clone());
    decode_dynamic(&wire, &mut rt).unwrap();

    let item_bits = rt.get_field_by_name("items").unwrap().as_list().unwrap()[0]
        .as_message()
        .unwrap()
        .get_field_by_name("val")
        .unwrap()
        .as_f32()
        .unwrap()
        .to_bits();
    assert_eq!(item_bits, (-0.0_f32).to_bits());

    let map_bits = rt
        .get_field_by_name("by_key")
        .unwrap()
        .as_map()
        .unwrap()
        .get(&MapKey::String("k0".to_owned()))
        .unwrap()
        .as_message()
        .unwrap()
        .get_field_by_name("val")
        .unwrap()
        .as_f32()
        .unwrap()
        .to_bits();
    assert_eq!(map_bits, (-0.0_f32).to_bits());

    // DecodeOptions enforced on decode_dynamic_with_options.
    assert!(
        decode_dynamic_with_options(
            &wire,
            &mut rt,
            DecodeOptions {
                max_message_bytes: 2,
                ..DecodeOptions::default()
            },
        )
        .is_err()
    );

    // 2. Populated Proto2 extension is rejected on encode, and wire extension tag is rejected on decode.
    let mut batch_with_ext = DynamicMessage::new(batch_desc.clone());
    batch_with_ext.set_extension(&ext_fd, ReflectValue::U32(42));
    assert!(encode_dynamic(&batch_with_ext, EncodeOptions::default()).is_err());

    let mut ext_wire = Vec::new();
    append_tag(&mut ext_wire, 105, WIRE_UINT);
    append_varint(&mut ext_wire, 42);
    let mut batch_dec = DynamicMessage::new(batch_desc);
    assert!(decode_dynamic(&ext_wire, &mut batch_dec).is_err());

    // 3. Proto2 group descriptor is rejected cleanly.
    let group_msg = DynamicMessage::new(group_desc.clone());
    assert!(encode_dynamic(&group_msg, EncodeOptions::default()).is_err());
    let mut group_wire = Vec::new();
    append_tag(&mut group_wire, 1, WIRE_SUB_MSG);
    append_varint(&mut group_wire, 0);
    let mut group_dec = DynamicMessage::new(group_desc);
    assert!(decode_dynamic(&group_wire, &mut group_dec).is_err());
}

#[cfg(feature = "buffa")]
#[test]
fn buffa_derive_and_dynamic_codec_roundtrip_neg_zero_and_group_rejection() {
    use std::sync::Arc;

    use buffa::{EnumValue, Enumeration, MessageField};
    use buffa_descriptor::generated::descriptor::{
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
        field_descriptor_proto::{Label, Type},
    };
    use buffa_descriptor::{
        DescriptorPool, DynamicMessage, ReflectMessage, ReflectMessageMut, Value as BuffaValue,
    };
    use omnibuf::buffa_codec::{
        decode_buffa_dynamic, decode_buffa_dynamic_with_options, encode_buffa_dynamic,
        schema_meta_from_buffa_name,
    };
    use omnibuf::wire::{WIRE_SUB_MSG, append_tag, append_varint};

    #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
    #[repr(i32)]
    enum LinkRole {
        #[default]
        Unspecified = 0,
        Core = 1,
        Edge = 2,
    }

    impl Enumeration for LinkRole {
        fn from_i32(value: i32) -> Option<Self> {
            match value {
                0 => Some(Self::Unspecified),
                1 => Some(Self::Core),
                2 => Some(Self::Edge),
                _ => None,
            }
        }

        fn to_i32(&self) -> i32 {
            *self as i32
        }

        fn proto_name(&self) -> &'static str {
            match self {
                Self::Unspecified => "UNSPECIFIED",
                Self::Core => "CORE",
                Self::Edge => "EDGE",
            }
        }
    }

    #[derive(Debug, Default, OmniBuf)]
    struct BuffaEndpoint {
        /// Field 1: `host`
        pub host: String,
        /// Field 2: `port`
        pub port: u32,
        pub __buffa_unknown_fields: buffa::UnknownFields,
        pub __buffa_cached_size: buffa::SizeCache,
    }

    impl buffa::DefaultInstance for BuffaEndpoint {
        fn default_instance() -> &'static Self {
            static INSTANCE: std::sync::LazyLock<BuffaEndpoint> =
                std::sync::LazyLock::new(BuffaEndpoint::default);
            &INSTANCE
        }
    }

    #[derive(Debug, Default, OmniBuf)]
    struct BuffaLinkRecord {
        /// Field 1: `endpoint`
        pub endpoint: MessageField<BuffaEndpoint>,
        /// Field 2: `role`
        pub role: EnumValue<LinkRole>,
        /// Field 3: `history`
        pub history: Vec<EnumValue<LinkRole>>,
        pub __buffa_unknown_fields: buffa::UnknownFields,
        pub __buffa_cached_size: buffa::SizeCache,
    }

    let orig = BuffaLinkRecord {
        endpoint: MessageField::some(BuffaEndpoint {
            host: "fra1-edge".to_owned(),
            port: 9090,
            ..Default::default()
        }),
        role: EnumValue::Known(LinkRole::Edge),
        history: vec![EnumValue::Known(LinkRole::Core), EnumValue::Unknown(77)],
        ..Default::default()
    };
    let wire = to_vec_with_options(&orig, EncodeOptions::self_describing()).unwrap();
    let rt: BuffaLinkRecord = from_slice(&wire).unwrap();
    assert_eq!(rt.endpoint.host, "fra1-edge");
    assert_eq!(rt.endpoint.port, 9090);
    assert_eq!(rt.role, EnumValue::Known(LinkRole::Edge));
    assert_eq!(
        rt.history,
        vec![EnumValue::Known(LinkRole::Core), EnumValue::Unknown(77)]
    );
    let json = decode_blind_json(&wire).unwrap();
    assert!(json.contains("\"endpoint\":{\"host\":\"fra1-edge\",\"port\":9090}"));
    assert!(json.contains("\"role\":2"));

    // Dynamic buffa_codec roundtrip with -0.0 preservation, DecodeOptions, and group rejection.
    let fds = FileDescriptorSet {
        file: vec![FileDescriptorProto {
            name: Some("buffa_dyn.proto".to_owned()),
            package: Some("buffapkg".to_owned()),
            syntax: Some("proto3".to_owned()),
            message_type: vec![
                DescriptorProto {
                    name: Some("Telemetry".to_owned()),
                    field: vec![
                        FieldDescriptorProto {
                            name: Some("f32_val".to_owned()),
                            number: Some(1),
                            label: Some(Label::LABEL_OPTIONAL),
                            r#type: Some(Type::TYPE_FLOAT),
                            proto3_optional: Some(true),
                            ..Default::default()
                        },
                        FieldDescriptorProto {
                            name: Some("f64_val".to_owned()),
                            number: Some(2),
                            label: Some(Label::LABEL_OPTIONAL),
                            r#type: Some(Type::TYPE_DOUBLE),
                            proto3_optional: Some(true),
                            ..Default::default()
                        },
                        FieldDescriptorProto {
                            name: Some("node".to_owned()),
                            number: Some(3),
                            label: Some(Label::LABEL_OPTIONAL),
                            r#type: Some(Type::TYPE_STRING),
                            ..Default::default()
                        },
                    ],
                    oneof_decl: vec![
                        buffa_descriptor::generated::descriptor::OneofDescriptorProto {
                            name: Some("_f32_val".to_owned()),
                            ..Default::default()
                        },
                        buffa_descriptor::generated::descriptor::OneofDescriptorProto {
                            name: Some("_f64_val".to_owned()),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                },
                DescriptorProto {
                    name: Some("LegacyGroupHolder".to_owned()),
                    field: vec![FieldDescriptorProto {
                        name: Some("legacygroup".to_owned()),
                        number: Some(1),
                        label: Some(Label::LABEL_OPTIONAL),
                        r#type: Some(Type::TYPE_GROUP),
                        type_name: Some(".buffapkg.Telemetry".to_owned()),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ],
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut fds = fds;
    fds.file[0].message_type[0].field[0].oneof_index = Some(0);
    fds.file[0].message_type[0].field[1].oneof_index = Some(1);

    let pool = Arc::new(DescriptorPool::new(fds).unwrap());
    let meta = schema_meta_from_buffa_name(&pool, "buffapkg.Telemetry").unwrap();
    assert_eq!(meta.type_name, "Telemetry");

    let tel_idx = pool.message_index("buffapkg.Telemetry").unwrap();
    let tel_md = pool.message(tel_idx);
    let f32_fd = tel_md.field_by_name("f32_val").unwrap();
    let f64_fd = tel_md.field_by_name("f64_val").unwrap();
    let node_fd = tel_md.field_by_name("node").unwrap();

    let mut dyn_msg = DynamicMessage::new(Arc::clone(&pool), tel_idx);
    dyn_msg.set(f32_fd, BuffaValue::F32(-0.0));
    dyn_msg.set(f64_fd, BuffaValue::F64(-0.0));
    dyn_msg.set(node_fd, BuffaValue::String("ams1".to_owned()));

    let dyn_wire = encode_buffa_dynamic(&dyn_msg, EncodeOptions::self_describing()).unwrap();
    let mut dyn_rt = DynamicMessage::new(Arc::clone(&pool), tel_idx);
    decode_buffa_dynamic(&dyn_wire, &mut dyn_rt).unwrap();

    let buffa_descriptor::ValueRef::F32(got_f32) = dyn_rt.get(f32_fd) else {
        panic!("expected F32");
    };
    let buffa_descriptor::ValueRef::F64(got_f64) = dyn_rt.get(f64_fd) else {
        panic!("expected F64");
    };
    assert_eq!(got_f32.to_bits(), (-0.0_f32).to_bits());
    assert_eq!(got_f64.to_bits(), (-0.0_f64).to_bits());

    assert!(
        decode_buffa_dynamic_with_options(
            &dyn_wire,
            &mut dyn_rt,
            DecodeOptions {
                max_message_bytes: 4,
                ..DecodeOptions::default()
            },
        )
        .is_err()
    );

    let grp_idx = pool.message_index("buffapkg.LegacyGroupHolder").unwrap();
    let grp_msg = DynamicMessage::new(Arc::clone(&pool), grp_idx);
    assert!(encode_buffa_dynamic(&grp_msg, EncodeOptions::default()).is_err());
    let mut grp_wire = Vec::new();
    append_tag(&mut grp_wire, 1, WIRE_SUB_MSG);
    append_varint(&mut grp_wire, 0);
    let mut grp_dec = DynamicMessage::new(pool, grp_idx);
    assert!(decode_buffa_dynamic(&grp_wire, &mut grp_dec).is_err());
}

#[test]
fn high_field_numbers_preserve_tags() {
    use omnibuf::message::codec;
    use omnibuf::wire::{MAX_FIELD_NUMBER, decode_varint};
    for field in [
        33_554_432,
        268_435_456,
        268_435_457,
        MAX_FIELD_NUMBER as u32,
    ] {
        let writers: &[fn(&mut Vec<u8>, u32)] = &[
            |b, f| codec::write_uint_field(b, f, 42),
            |b, f| codec::write_sint_field(b, f, -42),
            |b, f| codec::write_bool_field(b, f, true),
            |b, f| codec::write_fixed32_field(b, f, 42),
            |b, f| codec::write_fixed64_field(b, f, 42),
            |b, f| codec::write_sfixed32_field(b, f, -42),
            |b, f| codec::write_sfixed64_field(b, f, -42),
            |b, f| codec::write_float32_field(b, f, 1.5),
            |b, f| codec::write_float64_field(b, f, 1.5),
            |b, f| codec::write_string_field(b, f, "hello"),
            |b, f| codec::write_bytes_field(b, f, b"hello"),
            |b, f| codec::write_sub_msg_field(b, f, &Point2D::default(), false).unwrap(),
        ];
        for writer in writers {
            let mut bytes = Vec::new();
            writer(&mut bytes, field);
            let (tag, _) = decode_varint(&bytes).unwrap();
            assert_eq!(tag >> 4, u64::from(field));
        }
    }
}
