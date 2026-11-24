#![cfg(feature = "prost")]

use omnibuf::EncodeOptions;
use omnibuf::prost_codec::{decode_dynamic, encode_dynamic};
use omnibuf::wire::{Decoder, Encoder, read_float32};
use prost_reflect::{DescriptorPool, DynamicMessage};
use prost_types::field_descriptor_proto::{Label, Type};
use prost_types::{DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet};

/// Decoding `f13_float32 = -0.0` into a `prost_reflect::DynamicMessage` and then decoding
/// an empty `0`-byte packet (`merge = false`) into that same `DynamicMessage` must reset
/// `f13_float32` to `+0.0` (`bits == 0`), NOT leave `-0.0` (`0x8000_0000`) intact.
#[test]
fn prost_dynamic_reset_clears_negative_zero_float32() {
    let fds = FileDescriptorSet {
        file: vec![FileDescriptorProto {
            name: Some("negzero.proto".to_owned()),
            package: Some("nz.v1".to_owned()),
            syntax: Some("proto3".to_owned()),
            message_type: vec![DescriptorProto {
                name: Some("FloatResetMsg".to_owned()),
                field: vec![FieldDescriptorProto {
                    name: Some("f13_float32".to_owned()),
                    number: Some(13),
                    label: Some(Label::Optional as i32),
                    r#type: Some(Type::Float as i32),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    let pool = DescriptorPool::from_file_descriptor_set(fds).unwrap();
    let desc = pool.get_message_by_name("nz.v1.FloatResetMsg").unwrap();

    let mut enc = Encoder::default();
    enc.write_float32(13, -0.0_f32);
    let neg_zero_pkt = enc.into_vec();

    let mut dyn_msg = DynamicMessage::new(desc);
    decode_dynamic(&neg_zero_pkt, &mut dyn_msg).unwrap();
    assert_eq!(
        dyn_msg
            .get_field_by_name("f13_float32")
            .unwrap()
            .as_f32()
            .unwrap()
            .to_bits(),
        0x8000_0000
    );

    // Reset via non-merging decode of an empty 0-byte packet:
    decode_dynamic(&[], &mut dyn_msg).unwrap();
    let reencoded = encode_dynamic(&dyn_msg, EncodeOptions::default()).unwrap();

    let mem_bits = dyn_msg
        .get_field_by_name("f13_float32")
        .unwrap()
        .as_f32()
        .unwrap()
        .to_bits();
    let wire_bits = read_float32(&reencoded, 13).unwrap_or(0.0).to_bits();

    assert_eq!(
        mem_bits, 0,
        "DynamicMessage retained -0.0 (0x{mem_bits:08x}) after decoding empty packet with merge=false"
    );
    assert_eq!(
        wire_bits, 0,
        "re-encoded DynamicMessage emitted -0.0 (0x{wire_bits:08x}) after empty packet reset"
    );
}

/// `prost_codec::encode_dynamic` must emit fields in ascending field-number order
/// regardless of descriptor declaration order.
#[test]
fn prost_encode_sorts_fields_by_ascending_number() {
    let fds = FileDescriptorSet {
        file: vec![FileDescriptorProto {
            name: Some("order.proto".to_owned()),
            package: Some("ord.v1".to_owned()),
            syntax: Some("proto3".to_owned()),
            message_type: vec![DescriptorProto {
                name: Some("OutOfOrder".to_owned()),
                field: vec![
                    FieldDescriptorProto {
                        name: Some("tenth".to_owned()),
                        number: Some(10),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::Uint32 as i32),
                        ..Default::default()
                    },
                    FieldDescriptorProto {
                        name: Some("second".to_owned()),
                        number: Some(2),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::Uint32 as i32),
                        ..Default::default()
                    },
                    FieldDescriptorProto {
                        name: Some("fifth".to_owned()),
                        number: Some(5),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::Uint32 as i32),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    let pool = DescriptorPool::from_file_descriptor_set(fds).unwrap();
    let desc = pool.get_message_by_name("ord.v1.OutOfOrder").unwrap();
    let mut dyn_msg = DynamicMessage::new(desc);
    dyn_msg.set_field_by_name("tenth", prost_reflect::Value::U32(10));
    dyn_msg.set_field_by_name("second", prost_reflect::Value::U32(2));
    dyn_msg.set_field_by_name("fifth", prost_reflect::Value::U32(5));

    let wire = encode_dynamic(&dyn_msg, EncodeOptions::default()).unwrap();
    let mut dec = Decoder::new(&wire);
    let mut field_nums = Vec::new();
    while let Some((fnum, _wt)) = dec.next_tag().unwrap() {
        field_nums.push(fnum);
        let _ = dec.read_uint().unwrap();
    }
    assert_eq!(field_nums, vec![2, 5, 10]);
}

#[cfg(feature = "buffa")]
mod buffa_dynamic_tests {
    use std::sync::Arc;

    use buffa_descriptor::{ReflectMessage, ValueRef};
    use omnibuf::buffa_codec::decode_buffa_dynamic;
    use omnibuf::wire::{Encoder, WIRE_SUB_MSG, append_tag, append_varint};
    use prost::Message as _;
    use prost_types::field_descriptor_proto::{Label, Type};
    use prost_types::{
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
        OneofDescriptorProto,
    };

    fn build_buffa_pool(fds: &FileDescriptorSet) -> Arc<buffa_descriptor::DescriptorPool> {
        let bytes = fds.encode_to_vec();
        Arc::new(buffa_descriptor::DescriptorPool::decode(&bytes).unwrap())
    }

    /// Repeated `WireSubMsg` fields in `buffa_codec` merge in place without O(N^2)
    /// cloning, and oneof arm switches discard prior pending submessages cleanly.
    #[test]
    fn buffa_repeated_submsg_merge_and_oneof_switch() {
        let fds = FileDescriptorSet {
            file: vec![FileDescriptorProto {
                name: Some("merge.proto".to_owned()),
                package: Some("m.v1".to_owned()),
                syntax: Some("proto3".to_owned()),
                message_type: vec![
                    DescriptorProto {
                        name: Some("Child".to_owned()),
                        field: vec![
                            FieldDescriptorProto {
                                name: Some("a".to_owned()),
                                number: Some(1),
                                label: Some(Label::Optional as i32),
                                r#type: Some(Type::Uint32 as i32),
                                ..Default::default()
                            },
                            FieldDescriptorProto {
                                name: Some("b".to_owned()),
                                number: Some(2),
                                label: Some(Label::Optional as i32),
                                r#type: Some(Type::Uint32 as i32),
                                ..Default::default()
                            },
                        ],
                        ..Default::default()
                    },
                    DescriptorProto {
                        name: Some("Parent".to_owned()),
                        oneof_decl: vec![OneofDescriptorProto {
                            name: Some("choice".to_owned()),
                            options: None,
                        }],
                        field: vec![
                            FieldDescriptorProto {
                                name: Some("child".to_owned()),
                                number: Some(1),
                                label: Some(Label::Optional as i32),
                                r#type: Some(Type::Message as i32),
                                type_name: Some(".m.v1.Child".to_owned()),
                                ..Default::default()
                            },
                            FieldDescriptorProto {
                                name: Some("opt_child".to_owned()),
                                number: Some(2),
                                label: Some(Label::Optional as i32),
                                r#type: Some(Type::Message as i32),
                                type_name: Some(".m.v1.Child".to_owned()),
                                oneof_index: Some(0),
                                ..Default::default()
                            },
                            FieldDescriptorProto {
                                name: Some("opt_num".to_owned()),
                                number: Some(3),
                                label: Some(Label::Optional as i32),
                                r#type: Some(Type::Uint32 as i32),
                                oneof_index: Some(0),
                                ..Default::default()
                            },
                        ],
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
        };
        let pool = build_buffa_pool(&fds);
        let parent_idx = pool.message_index("m.v1.Parent").unwrap();

        // 1. Repeated WireSubMsg #1 (2000 occurrences) merges cleanly in O(N).
        let mut pkt = Vec::new();
        let mut first = Encoder::default();
        first.write_uint(1, 77);
        let first_bytes = first.into_vec();
        append_tag(&mut pkt, 1, WIRE_SUB_MSG);
        append_varint(&mut pkt, first_bytes.len() as u64);
        pkt.extend_from_slice(&first_bytes);

        for i in 1..2000u64 {
            let mut inc = Encoder::default();
            inc.write_uint(2, i);
            let inc_bytes = inc.into_vec();
            append_tag(&mut pkt, 1, WIRE_SUB_MSG);
            append_varint(&mut pkt, inc_bytes.len() as u64);
            pkt.extend_from_slice(&inc_bytes);
        }

        let mut msg = buffa_descriptor::DynamicMessage::new(Arc::clone(&pool), parent_idx);
        decode_buffa_dynamic(&pkt, &mut msg).unwrap();

        let md = pool.message(parent_idx);
        let child_fd = md.field(1).unwrap();
        let child_md = pool.message(pool.message_index("m.v1.Child").unwrap());
        let ValueRef::Message(sub) = msg.get(child_fd) else {
            panic!("expected merged child message");
        };
        assert!(matches!(
            sub.get(child_md.field(1).unwrap()),
            ValueRef::U32(77)
        ));
        assert!(matches!(
            sub.get(child_md.field(2).unwrap()),
            ValueRef::U32(1999)
        ));

        // 2. Oneof switch: opt_child (a=10) -> opt_num (99) -> opt_child (b=20)
        // must NOT retain a=10 from before the intervening scalar arm.
        let mut oneof_pkt = Vec::new();
        let mut c1 = Encoder::default();
        c1.write_uint(1, 10);
        let c1_bytes = c1.into_vec();
        append_tag(&mut oneof_pkt, 2, WIRE_SUB_MSG);
        append_varint(&mut oneof_pkt, c1_bytes.len() as u64);
        oneof_pkt.extend_from_slice(&c1_bytes);

        let mut mid = Encoder::default();
        mid.write_uint(3, 99);
        oneof_pkt.extend_from_slice(&mid.into_vec());

        let mut c2 = Encoder::default();
        c2.write_uint(2, 20);
        let c2_bytes = c2.into_vec();
        append_tag(&mut oneof_pkt, 2, WIRE_SUB_MSG);
        append_varint(&mut oneof_pkt, c2_bytes.len() as u64);
        oneof_pkt.extend_from_slice(&c2_bytes);

        let mut msg2 = buffa_descriptor::DynamicMessage::new(Arc::clone(&pool), parent_idx);
        decode_buffa_dynamic(&oneof_pkt, &mut msg2).unwrap();
        assert!(!msg2.has(md.field(3).unwrap()));
        let ValueRef::Message(sub2) = msg2.get(md.field(2).unwrap()) else {
            panic!("expected opt_child");
        };
        assert!(matches!(
            sub2.get(child_md.field(1).unwrap()),
            ValueRef::U32(0)
        ));
        assert!(matches!(
            sub2.get(child_md.field(2).unwrap()),
            ValueRef::U32(20)
        ));

        // 3. Oneof switch ending on scalar: opt_child -> opt_num (99) -> opt_num wins.
        let mut oneof_pkt2 = Vec::new();
        append_tag(&mut oneof_pkt2, 2, WIRE_SUB_MSG);
        append_varint(&mut oneof_pkt2, c1_bytes.len() as u64);
        oneof_pkt2.extend_from_slice(&c1_bytes);
        let mut tail = Encoder::default();
        tail.write_uint(3, 99);
        oneof_pkt2.extend_from_slice(&tail.into_vec());

        let mut msg3 = buffa_descriptor::DynamicMessage::new(Arc::clone(&pool), parent_idx);
        decode_buffa_dynamic(&oneof_pkt2, &mut msg3).unwrap();
        assert!(!msg3.has(md.field(2).unwrap()));
        assert!(matches!(msg3.get(md.field(3).unwrap()), ValueRef::U32(99)));
    }
}
