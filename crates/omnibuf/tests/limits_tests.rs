#![cfg(all(feature = "derive", feature = "prost"))]

use omnibuf::prost_codec::decode_dynamic_with_options;
use omnibuf::wire::{
    Encoder, WIRE_ARRAY, WIRE_BOOL_FALSE, WIRE_SUB_MSG, append_tag, append_varint,
    backpatch_container_len,
};
use omnibuf::{
    DecodeBlindOptions, DecodeOptions, OmniBuf, SchemaMeta, decode_blind_with_options,
    from_slice_with_options,
};
use prost_reflect::{DescriptorPool, DynamicMessage};
use prost_types::field_descriptor_proto::{Label, Type};
use prost_types::{DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet};

#[derive(Debug, Default, PartialEq, OmniBuf)]
struct EmptyRoot {}

/// A compact ~700-byte `Field #0` `SchemaMeta` carrying 200 field names allocates
/// more than 10 KB of `BTreeMap<u32, String>` + `String` heap memory and must be rejected when
/// `max_alloc_bytes = 1024`.
#[test]
fn field0_schema_meta_enforces_max_alloc_bytes_against_heap_amplification() {
    let mut meta = SchemaMeta {
        type_name: "Bomb".to_owned(),
        ..Default::default()
    };
    for i in 1..=200 {
        meta.fields.insert(i, "f".to_owned());
    }
    let pkt = meta.encode_field0().unwrap();
    assert!(
        pkt.len() < 1024,
        "expected compact wire packet < 1024 bytes, got {}",
        pkt.len()
    );

    let typed_res = from_slice_with_options::<EmptyRoot>(
        &pkt,
        DecodeOptions {
            max_alloc_bytes: 1024,
            ..DecodeOptions::default()
        },
    );
    let blind_res = decode_blind_with_options(
        &pkt,
        DecodeBlindOptions {
            max_alloc_bytes: 1024,
            ..DecodeBlindOptions::default()
        },
    );

    assert!(
        blind_res.is_err() && typed_res.is_err(),
        "expected max_alloc_bytes = 1024 to reject 200-entry Field #0 SchemaMeta (wire={} B); got typed={typed_res:?}, blind_ok={}",
        pkt.len(),
        blind_res.is_ok()
    );
}

#[derive(Clone, Debug, Default, PartialEq, OmniBuf)]
struct LargeSubMsg {
    #[omnibuf(id = 1)]
    w01: u64,
    #[omnibuf(id = 3)]
    w02: u64,
    #[omnibuf(id = 4)]
    w03: u64,
    #[omnibuf(id = 5)]
    w04: u64,
    #[omnibuf(id = 6)]
    w05: u64,
    #[omnibuf(id = 7)]
    w06: u64,
    #[omnibuf(id = 8)]
    w07: u64,
    #[omnibuf(id = 9)]
    w08: u64,
    #[omnibuf(id = 10)]
    w09: u64,
    #[omnibuf(id = 11)]
    w10: u64,
    #[omnibuf(id = 12)]
    w11: u64,
    #[omnibuf(id = 13)]
    w12: u64,
    #[omnibuf(id = 14)]
    w13: u64,
    #[omnibuf(id = 15)]
    w14: u64,
    #[omnibuf(id = 16)]
    w15: u64,
    #[omnibuf(id = 17)]
    w16: u64,
    #[omnibuf(id = 18)]
    w17: u64,
    #[omnibuf(id = 19)]
    w18: u64,
    #[omnibuf(id = 20)]
    w19: u64,
    #[omnibuf(id = 21)]
    w20: u64,
    #[omnibuf(id = 22)]
    w21: u64,
    #[omnibuf(id = 23)]
    w22: u64,
    #[omnibuf(id = 24)]
    w23: u64,
    #[omnibuf(id = 25)]
    w24: u64,
    #[omnibuf(id = 26)]
    w25: u64,
    #[omnibuf(id = 27)]
    w26: u64,
    #[omnibuf(id = 28)]
    w27: u64,
    #[omnibuf(id = 29)]
    w28: u64,
    #[omnibuf(id = 30)]
    w29: u64,
    #[omnibuf(id = 31)]
    w30: u64,
    #[omnibuf(id = 32)]
    w31: u64,
    #[omnibuf(id = 33)]
    w32: u64,
}

#[derive(Clone, Debug, Default, PartialEq, OmniBuf)]
struct LargeSubMsgVecHolder {
    #[omnibuf(id = 1)]
    items: Vec<LargeSubMsg>,
}

/// Decoding a ~100 KB `WireArray(WireSubMsg)` of 100,000 1-byte empty (`0x01`)
/// sub-messages into `Vec<LargeSubMsg>` allocates `100_000 * size_of::<LargeSubMsg>() > 25 MB`
/// on the heap and must be rejected when `max_alloc_bytes = 2_000_000`.
#[test]
fn sub_msg_vec_enforces_max_alloc_bytes_against_in_memory_struct_size() {
    const COUNT: usize = 100_000;
    assert!(
        COUNT * core::mem::size_of::<LargeSubMsg>() > 20_000_000,
        "LargeSubMsg must exceed 200 bytes so 100k elements allocate > 20 MB"
    );

    let mut pkt = Vec::with_capacity(COUNT + 16);
    append_tag(&mut pkt, 1, WIRE_ARRAY);
    let len_pos = pkt.len();
    pkt.extend_from_slice(&[0, 0, WIRE_SUB_MSG]);
    append_varint(&mut pkt, COUNT as u64);
    // Each `0x01` is a valid 1-byte Prefix-Varint encoding `byte_len = 0` (empty sub-message).
    pkt.resize(pkt.len() + COUNT, 0x01);
    backpatch_container_len(&mut pkt, len_pos);

    let res = from_slice_with_options::<LargeSubMsgVecHolder>(
        &pkt,
        DecodeOptions {
            max_alloc_bytes: 2_000_000,
            ..DecodeOptions::default()
        },
    );

    assert!(
        res.is_err(),
        "expected max_alloc_bytes = 2_000_000 to reject {} B Vec<LargeSubMsg> allocation from {} B packet",
        COUNT * core::mem::size_of::<LargeSubMsg>(),
        pkt.len()
    );
}

/// `decode_blind_with_options` must charge per-entry map/key overhead on new field
/// insertions so many distinct scalar or empty `WireSubMsg` fields cannot bypass `max_alloc_bytes`.
#[test]
fn blind_decode_charges_per_field_entry_allocation() {
    let mut scalar_pkt = Vec::new();
    for fnum in 1..=200u32 {
        append_tag(&mut scalar_pkt, fnum, WIRE_BOOL_FALSE);
    }
    let res = decode_blind_with_options(
        &scalar_pkt,
        DecodeBlindOptions {
            max_alloc_bytes: 1024,
            ..DecodeBlindOptions::default()
        },
    );
    assert!(
        res.is_err(),
        "expected 200 distinct bool fields ({} B wire) to exceed max_alloc_bytes=1024",
        scalar_pkt.len()
    );

    let mut submsg_pkt = Vec::new();
    for fnum in 1..=200u32 {
        append_tag(&mut submsg_pkt, fnum, WIRE_SUB_MSG);
        append_varint(&mut submsg_pkt, 0);
    }
    let res_sub = decode_blind_with_options(
        &submsg_pkt,
        DecodeBlindOptions {
            max_alloc_bytes: 1024,
            ..DecodeBlindOptions::default()
        },
    );
    assert!(
        res_sub.is_err(),
        "expected 200 distinct empty WireSubMsg fields ({} B wire) to exceed max_alloc_bytes=1024",
        submsg_pkt.len()
    );
}

/// Merging a second `WireSubMsg` onto a `Cow::Borrowed` first occurrence must charge
/// `existing.len() + sub_bytes.len()` before `existing.to_mut()` clones the first payload.
#[test]
fn blind_decode_submsg_merge_charges_borrowed_existing_len() {
    let mut inner = Encoder::default();
    inner.write_string(1, &"x".repeat(4000));
    let inner_bytes = inner.into_vec();

    let mut pkt = Vec::new();
    append_tag(&mut pkt, 1, WIRE_SUB_MSG);
    append_varint(&mut pkt, inner_bytes.len() as u64);
    pkt.extend_from_slice(&inner_bytes);
    // Second occurrence is empty (0 bytes), triggering `existing.to_mut()` copy of `inner_bytes`.
    append_tag(&mut pkt, 1, WIRE_SUB_MSG);
    append_varint(&mut pkt, 0);

    let res = decode_blind_with_options(
        &pkt,
        DecodeBlindOptions {
            max_alloc_bytes: 2048,
            ..DecodeBlindOptions::default()
        },
    );
    assert!(
        res.is_err(),
        "expected WireSubMsg merge copying {} B existing slice to exceed max_alloc_bytes=2048",
        inner_bytes.len()
    );
}

/// `decode_dynamic_with_options` must enforce `max_alloc_bytes` during
/// materialization of large `WireArray(WireSubMsg)` payloads.
#[test]
fn prost_dynamic_enforces_max_alloc_bytes() {
    let fds = FileDescriptorSet {
        file: vec![FileDescriptorProto {
            name: Some("arr_bomb.proto".to_owned()),
            package: Some("bomb.v1".to_owned()),
            syntax: Some("proto3".to_owned()),
            message_type: vec![
                DescriptorProto {
                    name: Some("Empty".to_owned()),
                    ..Default::default()
                },
                DescriptorProto {
                    name: Some("Holder".to_owned()),
                    field: vec![FieldDescriptorProto {
                        name: Some("items".to_owned()),
                        number: Some(1),
                        label: Some(Label::Repeated as i32),
                        r#type: Some(Type::Message as i32),
                        type_name: Some(".bomb.v1.Empty".to_owned()),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ],
            ..Default::default()
        }],
    };
    let pool = DescriptorPool::from_file_descriptor_set(fds).unwrap();
    let desc = pool.get_message_by_name("bomb.v1.Holder").unwrap();

    const COUNT: usize = 50_000;
    let mut pkt = Vec::with_capacity(COUNT + 16);
    append_tag(&mut pkt, 1, WIRE_ARRAY);
    let len_pos = pkt.len();
    pkt.extend_from_slice(&[0, 0, WIRE_SUB_MSG]);
    append_varint(&mut pkt, COUNT as u64);
    pkt.resize(pkt.len() + COUNT, 0x01);
    backpatch_container_len(&mut pkt, len_pos);

    let mut dyn_msg = DynamicMessage::new(desc);
    let res = decode_dynamic_with_options(
        &pkt,
        &mut dyn_msg,
        DecodeOptions {
            max_alloc_bytes: 512 * 1024,
            ..DecodeOptions::default()
        },
    );
    assert!(
        res.is_err(),
        "expected prost decode_dynamic_with_options to reject 50k DynamicMessage array under 512 KiB budget"
    );
}

/// `WIRE_STRING` and `WIRE_BYTES` payloads must not be double-charged
/// against `DecodeOptions::max_alloc_bytes` (once in pre-validation and again in scalar decode).
#[test]
fn prost_string_and_bytes_not_double_charged() {
    let fds = FileDescriptorSet {
        file: vec![FileDescriptorProto {
            name: Some("str_budget.proto".to_owned()),
            package: Some("sb.v1".to_owned()),
            syntax: Some("proto3".to_owned()),
            message_type: vec![DescriptorProto {
                name: Some("Payload".to_owned()),
                field: vec![
                    FieldDescriptorProto {
                        name: Some("text".to_owned()),
                        number: Some(1),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::String as i32),
                        ..Default::default()
                    },
                    FieldDescriptorProto {
                        name: Some("raw".to_owned()),
                        number: Some(2),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::Bytes as i32),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };
    let pool = DescriptorPool::from_file_descriptor_set(fds).unwrap();
    let desc = pool.get_message_by_name("sb.v1.Payload").unwrap();

    let mut enc_str = Encoder::default();
    enc_str.write_string(1, &"a".repeat(1000));
    let wire_str = enc_str.into_vec();

    let mut msg = DynamicMessage::new(desc.clone());
    decode_dynamic_with_options(
        &wire_str,
        &mut msg,
        DecodeOptions {
            max_alloc_bytes: 1500,
            ..DecodeOptions::default()
        },
    )
    .expect("1000-byte string must fit within 1500-byte alloc budget");
    assert_eq!(
        msg.get_field_by_name("text").unwrap().as_str(),
        Some("a".repeat(1000).as_str())
    );

    let mut msg_tight = DynamicMessage::new(desc.clone());
    assert!(
        decode_dynamic_with_options(
            &wire_str,
            &mut msg_tight,
            DecodeOptions {
                max_alloc_bytes: 999,
                ..DecodeOptions::default()
            },
        )
        .is_err(),
        "1000-byte string must still fail under 999-byte alloc budget"
    );

    let mut enc_bytes = Encoder::default();
    enc_bytes.write_bytes(2, &vec![0x5Au8; 1000]);
    let wire_bytes = enc_bytes.into_vec();

    let mut msg_b = DynamicMessage::new(desc.clone());
    decode_dynamic_with_options(
        &wire_bytes,
        &mut msg_b,
        DecodeOptions {
            max_alloc_bytes: 1500,
            ..DecodeOptions::default()
        },
    )
    .expect("1000-byte bytes field must fit within 1500-byte alloc budget");
    assert_eq!(
        msg_b
            .get_field_by_name("raw")
            .unwrap()
            .as_bytes()
            .map(|b| b.len()),
        Some(1000)
    );

    let mut msg_b_tight = DynamicMessage::new(desc);
    assert!(
        decode_dynamic_with_options(
            &wire_bytes,
            &mut msg_b_tight,
            DecodeOptions {
                max_alloc_bytes: 999,
                ..DecodeOptions::default()
            },
        )
        .is_err(),
        "1000-byte bytes field must still fail under 999-byte alloc budget"
    );
}

#[derive(OmniBuf, Default, PartialEq, Debug)]
struct LargeBudgetLeaf {
    #[omnibuf(id = 1)]
    a: u64,
    #[omnibuf(id = 2)]
    b: u64,
    #[omnibuf(id = 3)]
    c: u64,
    #[omnibuf(id = 4)]
    d: u64,
    #[omnibuf(id = 5)]
    e: u64,
    #[omnibuf(id = 6)]
    f: u64,
    #[omnibuf(id = 7)]
    g: u64,
    #[omnibuf(id = 8)]
    h: u64,
    #[omnibuf(id = 9)]
    s1: String,
    #[omnibuf(id = 10)]
    s2: String,
    #[omnibuf(id = 11)]
    s3: String,
    #[omnibuf(id = 12)]
    s4: String,
}

#[derive(OmniBuf, PartialEq, Debug)]
enum BoxedOneofPayload {
    #[omnibuf(id = 1)]
    Leaf(Box<LargeBudgetLeaf>),
}

#[derive(OmniBuf, Default, PartialEq, Debug)]
struct BoxedOneofHolder {
    #[omnibuf(oneof)]
    payload: Option<BoxedOneofPayload>,
}

/// Boxed oneof sub-message decoding must charge `size_of::<M>()`
/// against `DecodeOptions::max_alloc_bytes`.
#[test]
fn derive_boxed_oneof_charges_alloc_budget() {
    let orig = BoxedOneofHolder {
        payload: Some(BoxedOneofPayload::Leaf(Box::new(LargeBudgetLeaf {
            a: 42,
            ..Default::default()
        }))),
    };
    let wire = omnibuf::to_vec(&orig).unwrap();
    let leaf_size = core::mem::size_of::<LargeBudgetLeaf>();
    assert!(leaf_size >= 128);

    let err = from_slice_with_options::<BoxedOneofHolder>(
        &wire,
        DecodeOptions {
            max_alloc_bytes: leaf_size - 1,
            ..DecodeOptions::default()
        },
    );
    assert!(
        err.is_err(),
        "expected boxed oneof decode to fail when max_alloc_bytes ({}) < size_of::<LargeBudgetLeaf>() ({leaf_size})",
        leaf_size - 1
    );

    let decoded = from_slice_with_options::<BoxedOneofHolder>(
        &wire,
        DecodeOptions {
            max_alloc_bytes: leaf_size + 64,
            ..DecodeOptions::default()
        },
    )
    .expect("boxed oneof decode should succeed with sufficient alloc budget");
    assert_eq!(decoded, orig);
}

#[cfg(feature = "buffa")]
mod buffa_limits_tests {
    use std::sync::Arc;

    use buffa_descriptor::{ReflectMessage, ValueRef};
    use omnibuf::DecodeOptions;
    use omnibuf::buffa_codec::decode_buffa_dynamic_with_options;
    use omnibuf::wire::{
        Encoder, WIRE_ARRAY, WIRE_SUB_MSG, append_tag, append_varint, backpatch_container_len,
    };
    use prost::Message as _;
    use prost_types::field_descriptor_proto::{Label, Type};
    use prost_types::{
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
    };

    fn build_buffa_pool(fds: &FileDescriptorSet) -> Arc<buffa_descriptor::DescriptorPool> {
        let bytes = fds.encode_to_vec();
        Arc::new(buffa_descriptor::DescriptorPool::decode(&bytes).unwrap())
    }

    /// `decode_buffa_dynamic_with_options` must enforce `max_alloc_bytes`
    /// during materialization of large `WireArray(WireSubMsg)` payloads.
    #[test]
    fn buffa_dynamic_enforces_max_alloc_bytes() {
        let fds = FileDescriptorSet {
            file: vec![FileDescriptorProto {
                name: Some("buffa_bomb.proto".to_owned()),
                package: Some("bb.v1".to_owned()),
                syntax: Some("proto3".to_owned()),
                message_type: vec![
                    DescriptorProto {
                        name: Some("Empty".to_owned()),
                        ..Default::default()
                    },
                    DescriptorProto {
                        name: Some("Holder".to_owned()),
                        field: vec![FieldDescriptorProto {
                            name: Some("items".to_owned()),
                            number: Some(1),
                            label: Some(Label::Repeated as i32),
                            r#type: Some(Type::Message as i32),
                            type_name: Some(".bb.v1.Empty".to_owned()),
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
        };
        let pool = build_buffa_pool(&fds);
        let holder_idx = pool.message_index("bb.v1.Holder").unwrap();

        const COUNT: usize = 50_000;
        let mut pkt = Vec::with_capacity(COUNT + 16);
        append_tag(&mut pkt, 1, WIRE_ARRAY);
        let len_pos = pkt.len();
        pkt.extend_from_slice(&[0, 0, WIRE_SUB_MSG]);
        append_varint(&mut pkt, COUNT as u64);
        pkt.resize(pkt.len() + COUNT, 0x01);
        backpatch_container_len(&mut pkt, len_pos);

        let mut dyn_msg = buffa_descriptor::DynamicMessage::new(pool, holder_idx);
        let res = decode_buffa_dynamic_with_options(
            &pkt,
            &mut dyn_msg,
            DecodeOptions {
                max_alloc_bytes: 512 * 1024,
                ..DecodeOptions::default()
            },
        );
        assert!(
            res.is_err(),
            "expected buffa decode_buffa_dynamic_with_options to reject 50k DynamicMessage array under 512 KiB budget"
        );
    }

    /// `WIRE_STRING` and `WIRE_BYTES` payloads must not be double-charged
    /// against `DecodeOptions::max_alloc_bytes` in `buffa_codec`.
    #[test]
    fn buffa_string_and_bytes_not_double_charged() {
        let fds = FileDescriptorSet {
            file: vec![FileDescriptorProto {
                name: Some("buffa_str_budget.proto".to_owned()),
                package: Some("bsb.v1".to_owned()),
                syntax: Some("proto3".to_owned()),
                message_type: vec![DescriptorProto {
                    name: Some("Payload".to_owned()),
                    field: vec![
                        FieldDescriptorProto {
                            name: Some("text".to_owned()),
                            number: Some(1),
                            label: Some(Label::Optional as i32),
                            r#type: Some(Type::String as i32),
                            ..Default::default()
                        },
                        FieldDescriptorProto {
                            name: Some("raw".to_owned()),
                            number: Some(2),
                            label: Some(Label::Optional as i32),
                            r#type: Some(Type::Bytes as i32),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        let pool = build_buffa_pool(&fds);
        let msg_idx = pool.message_index("bsb.v1.Payload").unwrap();
        let md = pool.message(msg_idx);

        let mut enc_str = Encoder::default();
        enc_str.write_string(1, &"a".repeat(1000));
        let wire_str = enc_str.into_vec();

        let mut msg = buffa_descriptor::DynamicMessage::new(Arc::clone(&pool), msg_idx);
        decode_buffa_dynamic_with_options(
            &wire_str,
            &mut msg,
            DecodeOptions {
                max_alloc_bytes: 1500,
                ..DecodeOptions::default()
            },
        )
        .expect("1000-byte string must fit within 1500-byte alloc budget in buffa");
        assert!(matches!(
            msg.get(md.field(1).unwrap()),
            ValueRef::String(s) if s.len() == 1000
        ));

        let mut msg_tight = buffa_descriptor::DynamicMessage::new(Arc::clone(&pool), msg_idx);
        assert!(
            decode_buffa_dynamic_with_options(
                &wire_str,
                &mut msg_tight,
                DecodeOptions {
                    max_alloc_bytes: 999,
                    ..DecodeOptions::default()
                },
            )
            .is_err(),
            "1000-byte string must still fail under 999-byte alloc budget in buffa"
        );

        let mut enc_bytes = Encoder::default();
        enc_bytes.write_bytes(2, &vec![0x5Au8; 1000]);
        let wire_bytes = enc_bytes.into_vec();

        let mut msg_b = buffa_descriptor::DynamicMessage::new(Arc::clone(&pool), msg_idx);
        decode_buffa_dynamic_with_options(
            &wire_bytes,
            &mut msg_b,
            DecodeOptions {
                max_alloc_bytes: 1500,
                ..DecodeOptions::default()
            },
        )
        .expect("1000-byte bytes field must fit within 1500-byte alloc budget in buffa");
        assert!(matches!(
            msg_b.get(md.field(2).unwrap()),
            ValueRef::Bytes(b) if b.len() == 1000
        ));

        let mut msg_b_tight = buffa_descriptor::DynamicMessage::new(pool, msg_idx);
        assert!(
            decode_buffa_dynamic_with_options(
                &wire_bytes,
                &mut msg_b_tight,
                DecodeOptions {
                    max_alloc_bytes: 999,
                    ..DecodeOptions::default()
                },
            )
            .is_err(),
            "1000-byte bytes field must still fail under 999-byte alloc budget in buffa"
        );
    }

    #[derive(omnibuf::OmniBuf, Default, Debug)]
    struct BuffaMessageFieldHolder {
        #[omnibuf(id = 1)]
        child: ::buffa::MessageField<super::LargeBudgetLeaf>,
    }

    /// `codec::read_buffa_message_field` must charge `size_of::<M>()`
    /// against `DecodeOptions::max_alloc_bytes` before boxing.
    #[test]
    fn buffa_message_field_charges_alloc_budget() {
        use omnibuf::from_slice_with_options;

        let orig = BuffaMessageFieldHolder {
            child: ::buffa::MessageField::some(super::LargeBudgetLeaf {
                a: 7,
                ..Default::default()
            }),
        };
        let wire = omnibuf::to_vec(&orig).unwrap();
        let leaf_size = core::mem::size_of::<super::LargeBudgetLeaf>();

        let err = from_slice_with_options::<BuffaMessageFieldHolder>(
            &wire,
            DecodeOptions {
                max_alloc_bytes: leaf_size - 1,
                ..DecodeOptions::default()
            },
        );
        assert!(
            err.is_err(),
            "expected buffa MessageField decode to fail when max_alloc_bytes ({}) < size_of::<LargeBudgetLeaf>() ({leaf_size})",
            leaf_size - 1
        );

        let decoded = from_slice_with_options::<BuffaMessageFieldHolder>(
            &wire,
            DecodeOptions {
                max_alloc_bytes: leaf_size + 64,
                ..DecodeOptions::default()
            },
        )
        .expect("buffa MessageField decode should succeed with sufficient alloc budget");
        assert_eq!(decoded.child.as_option(), orig.child.as_option());
    }
}
