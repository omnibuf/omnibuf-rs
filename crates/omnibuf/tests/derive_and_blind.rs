use std::collections::{BTreeMap, HashMap};

use omnibuf::wire::{Encoder, WIRE_STRING, WIRE_SUB_MSG, WIRE_UINT, append_tag, append_varint};
use omnibuf::{
    BlindValue, EncodeOptions, OmniBuf, SchemaMeta, decode_blind, decode_blind_json, decode_into,
    from_slice, stringify_blind_json, to_vec, to_vec_deterministic, to_vec_with_options,
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
    meta.append_field0(&mut packet);

    let map = decode_blind(&packet).unwrap();
    assert_eq!(map.get("max_u64"), Some(&BlindValue::Uint(u64::MAX)));
    assert_eq!(map.get("min_i64"), Some(&BlindValue::Int(i64::MIN)));

    let json = decode_blind_json(&packet).unwrap();
    assert!(json.contains("\"max_u64\":18446744073709551615"));
    assert!(json.contains("\"min_i64\":-9223372036854775808"));
    assert!(json.contains("\"lat_f32\":50.1109"));
    assert!(json.contains("\"raw_payload\":\"aGVsbG8=\""));
    assert_eq!(stringify_blind_json(&map, None, true), json);

    // Non-finite float returns "{}" fallback from decode_blind_json.
    let mut nan_enc = Encoder::default();
    nan_enc.write_float64(1, f64::NAN);
    let nan_pkt = nan_enc.into_vec();
    let nan_map = decode_blind(&nan_pkt).unwrap();
    assert!(matches!(
        nan_map.get("field_1"),
        Some(BlindValue::Float64(v)) if v.is_nan()
    ));
    assert_eq!(decode_blind_json(&nan_pkt).unwrap(), "{}");
}

#[test]
fn blind_decoder_rejects_name_collision_and_wire_shape_conflict() {
    // 1. Two distinct field numbers mapped to the same name in Field #0 must error.
    let mut meta = SchemaMeta::default();
    meta.fields.insert(1, "dup_name".to_owned());
    meta.fields.insert(2, "dup_name".to_owned());
    let mut pkt = Vec::new();
    meta.append_field0(&mut pkt);
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
