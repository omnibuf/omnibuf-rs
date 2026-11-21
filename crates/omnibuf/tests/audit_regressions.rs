#![cfg(all(feature = "derive", feature = "prost"))]

use omnibuf::prost_codec::{decode_dynamic, decode_dynamic_with_options, encode_dynamic};
use omnibuf::wire::{
    Decoder, Encoder, WIRE_ARRAY, WIRE_BOOL_FALSE, WIRE_SUB_MSG, append_tag, append_varint,
    backpatch_container_len, read_float32,
};
use omnibuf::{
    DecodeBlindOptions, DecodeOptions, EncodeOptions, Message, OmniBuf, SchemaMeta,
    decode_blind_json, decode_blind_with_options, from_slice_with_options, to_vec_with_options,
};
use prost_reflect::{DescriptorPool, DynamicMessage};
use prost_types::field_descriptor_proto::{Label, Type};
use prost_types::{DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet};

#[path = "../../conformance-rs/src/generated/omnibuf/bench/peer_omnibuf.rs"]
mod peer_omnibuf;

/// RS-2: `OpaquePeerUpdate::marshal_append` and `try_marshal_append` must preserve an existing
/// framing prefix (`[0xDE, 0xAD, 0xBE, 0xEF]`) in `dst` both when `dirty == 0` and when `dirty != 0`.
#[test]
fn rs_2_opaque_peer_update_marshal_append_preserves_framing_prefix() {
    let orig = peer_omnibuf::PeerUpdate {
        asn: 64512,
        router_id: "edge-fra-01".to_owned(),
        sequence: 7,
        active: true,
        ..Default::default()
    };
    let raw = orig.marshal_omnibuf();
    let prefix = [0xDE, 0xAD, 0xBE, 0xEF];

    // 1. Clean (`dirty == 0`) marshal_append & try_marshal_append
    let clean_view = peer_omnibuf::OpaquePeerUpdate::new(&raw);

    let mut dst_clean = prefix.to_vec();
    clean_view.marshal_append(&mut dst_clean);
    assert!(
        dst_clean.starts_with(&prefix),
        "clean marshal_append wiped framing prefix: got {:?}",
        &dst_clean[..dst_clean.len().min(8)]
    );
    assert_eq!(
        peer_omnibuf::PeerUpdate::from_omnibuf(&dst_clean[4..]).unwrap(),
        orig
    );

    let mut dst_try_clean = prefix.to_vec();
    clean_view.try_marshal_append(&mut dst_try_clean).unwrap();
    assert!(
        dst_try_clean.starts_with(&prefix),
        "clean try_marshal_append wiped framing prefix: got {:?}",
        &dst_try_clean[..dst_try_clean.len().min(8)]
    );
    assert_eq!(
        peer_omnibuf::PeerUpdate::from_omnibuf(&dst_try_clean[4..]).unwrap(),
        orig
    );

    // 2. Dirty (`dirty != 0`) marshal_append & try_marshal_append
    let mut dirty_view = peer_omnibuf::OpaquePeerUpdate::new(&raw);
    dirty_view.set_sequence(42);

    let mut dst_dirty = prefix.to_vec();
    dirty_view.marshal_append(&mut dst_dirty);
    assert!(
        dst_dirty.starts_with(&prefix),
        "dirty marshal_append wiped framing prefix: got {:?}",
        &dst_dirty[..dst_dirty.len().min(8)]
    );
    let decoded_dirty = peer_omnibuf::PeerUpdate::from_omnibuf(&dst_dirty[4..]).unwrap();
    assert_eq!(decoded_dirty.sequence, 42);

    let mut dst_try_dirty = prefix.to_vec();
    dirty_view.try_marshal_append(&mut dst_try_dirty).unwrap();
    assert!(
        dst_try_dirty.starts_with(&prefix),
        "dirty try_marshal_append wiped framing prefix: got {:?}",
        &dst_try_dirty[..dst_try_dirty.len().min(8)]
    );
    let decoded_try_dirty = peer_omnibuf::PeerUpdate::from_omnibuf(&dst_try_dirty[4..]).unwrap();
    assert_eq!(decoded_try_dirty.sequence, 42);
}

#[derive(Debug, Default, PartialEq, OmniBuf)]
struct EmptyRoot {}

/// RS-3: A compact ~700-byte `Field #0` `SchemaMeta` carrying 200 field names allocates
/// more than 10 KB of `BTreeMap<u32, String>` + `String` heap memory and must be rejected when
/// `max_alloc_bytes = 1024`.
#[test]
fn rs_3_field0_schema_meta_enforces_max_alloc_bytes_against_heap_amplification() {
    let mut meta = SchemaMeta {
        type_name: "Bomb".to_owned(),
        ..Default::default()
    };
    for i in 1..=200 {
        meta.fields.insert(i, "f".to_owned());
    }
    let pkt = meta.encode_field0();
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

#[derive(Debug, Default, PartialEq, OmniBuf)]
struct Uint8ArrayMsg {
    #[omnibuf(id = 1, wire = "uint")]
    vals: Vec<u8>,
}

/// RS-4: Encoding `Vec<u8>` (10,000 1-byte `u8` varint elements) via `write_varint_vec_field`
/// must not blindly reserve `9 * count` (>90 KB) capacity for elements that take at most 2 bytes each.
#[test]
fn rs_4_write_varint_vec_field_does_not_over_reserve_9x_capacity() {
    let msg = Uint8ArrayMsg {
        vals: vec![1u8; 10_000],
    };
    let mut dst = Vec::new();
    msg.encode_omnibuf_append(&mut dst, false).unwrap();

    assert!(
        dst.capacity() < 90_000,
        "write_varint_vec_field over-reserved 9x capacity: capacity={} for encoded len={}",
        dst.capacity(),
        dst.len()
    );
}

#[derive(Clone, Debug, Default, PartialEq, OmniBuf)]
struct InnerCell {
    #[omnibuf(id = 1, name = "cell_tag")]
    cell_tag: String,
}

#[derive(Clone, Debug, Default, PartialEq, OmniBuf)]
struct MatrixMsg {
    #[omnibuf(id = 1, name = "grid")]
    grid: Vec<Vec<InnerCell>>,
}

/// RS-7a: `#[derive(OmniBuf)]` struct with `Vec<Vec<InnerCell>>` encoded with
/// `EncodeOptions::self_describing()` must include `InnerCell`'s `SchemaMeta` so `decode_blind`
/// resolves `"cell_tag"` instead of falling back to `"field_1"`.
#[test]
fn rs_7a_derive_nested_vec_of_submsg_emits_child_schema_meta() {
    let msg = MatrixMsg {
        grid: vec![vec![InnerCell {
            cell_tag: "alpha".to_owned(),
        }]],
    };
    let pkt = to_vec_with_options(&msg, EncodeOptions::self_describing()).unwrap();
    let json = decode_blind_json(&pkt).unwrap();

    assert!(
        json.contains("\"cell_tag\":\"alpha\""),
        "decode_blind_json failed to resolve inner Vec<Vec<InnerCell>> field name: got {json}"
    );
}

#[derive(Clone, Debug, PartialEq, OmniBuf)]
enum RawKeywordOneof {
    #[omnibuf(id = 1)]
    r#Type(String),
}

#[derive(Clone, Debug, Default, PartialEq, OmniBuf)]
struct RawOneofHolder {
    #[omnibuf(oneof, tags = "1")]
    kind: Option<RawKeywordOneof>,
}

/// RS-7b: `#[derive(OmniBuf)]` oneof enum variant `r#Type(String)` must strip the `r#` raw-ident
/// prefix before snake_casing so `SchemaMeta` records `"type"`, not `"r#_type"`.
#[test]
fn rs_7b_derive_oneof_raw_ident_strips_raw_prefix_in_schema_meta() {
    let meta = RawOneofHolder::schema_meta();
    assert_eq!(
        meta.fields.get(&1).map(String::as_str),
        Some("type"),
        "expected oneof variant `r#Type` schema field name to be \"type\", got {:?}",
        meta.fields.get(&1)
    );
}

/// RS-8: Decoding `f13_float32 = -0.0` into a `prost_reflect::DynamicMessage` and then decoding
/// an empty `0`-byte packet (`merge = false`) into that same `DynamicMessage` must reset
/// `f13_float32` to `+0.0` (`bits == 0`), NOT leave `-0.0` (`0x8000_0000`) intact.
#[test]
fn rs_8_prost_dynamic_reset_clears_negative_zero_float32() {
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

/// RS-9 / RS-10: Decoding a ~100 KB `WireArray(WireSubMsg)` of 100,000 1-byte empty (`0x01`)
/// sub-messages into `Vec<LargeSubMsg>` allocates `100_000 * size_of::<LargeSubMsg>() > 25 MB`
/// on the heap and must be rejected when `max_alloc_bytes = 2_000_000`.
#[test]
fn rs_10_sub_msg_vec_enforces_max_alloc_bytes_against_in_memory_struct_size() {
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

/// Audit #1a: `decode_blind_with_options` must charge per-entry map/key overhead on new field
/// insertions so many distinct scalar or empty `WireSubMsg` fields cannot bypass `max_alloc_bytes`.
#[test]
fn audit_1a_blind_decode_charges_per_field_entry_allocation() {
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

/// Audit #1b: Merging a second `WireSubMsg` onto a `Cow::Borrowed` first occurrence must charge
/// `existing.len() + sub_bytes.len()` before `existing.to_mut()` clones the first payload.
#[test]
fn audit_1b_blind_decode_submsg_merge_charges_borrowed_existing_len() {
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

/// Audit #3 (prost): `decode_dynamic_with_options` must enforce `max_alloc_bytes` during
/// materialization of large `WireArray(WireSubMsg)` payloads.
#[test]
fn audit_3_prost_dynamic_enforces_max_alloc_bytes() {
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

/// Audit #5b: `prost_codec::encode_dynamic` must emit fields in ascending field-number order
/// regardless of descriptor declaration order.
#[test]
fn audit_5b_prost_encode_sorts_fields_by_ascending_number() {
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

/// Audit #5c: `Decoder::read_fixed32`/`read_fixed64` and `read_elem_fixed32`/`read_elem_fixed64`
/// must return `Err` instead of overflowing when `pos` is near `usize::MAX`.
#[test]
fn audit_5c_fixed_readers_use_checked_add() {
    let mut dec = Decoder::new(&[1, 2, 3, 4, 5, 6, 7, 8]);
    dec.set_position(usize::MAX - 2);
    assert!(dec.read_fixed32().is_err());
    assert!(dec.read_fixed64().is_err());

    assert!(omnibuf::codec::read_elem_fixed32(&[0; 8], usize::MAX - 2).is_err());
    assert!(omnibuf::codec::read_elem_fixed64(&[0; 8], usize::MAX - 4).is_err());
}

#[cfg(feature = "buffa")]
mod buffa_audit_tests {
    use std::sync::Arc;

    use buffa_descriptor::{ReflectMessage, ValueRef};
    use omnibuf::DecodeOptions;
    use omnibuf::buffa_codec::{decode_buffa_dynamic, decode_buffa_dynamic_with_options};
    use omnibuf::wire::{
        Encoder, WIRE_ARRAY, WIRE_SUB_MSG, append_tag, append_varint, backpatch_container_len,
    };
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

    /// Audit #2: Repeated `WireSubMsg` fields in `buffa_codec` merge in place without O(N^2)
    /// cloning, and oneof arm switches discard prior pending submessages cleanly.
    #[test]
    fn audit_2_buffa_repeated_submsg_merge_and_oneof_switch() {
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

    /// Audit #3 (buffa): `decode_buffa_dynamic_with_options` must enforce `max_alloc_bytes`
    /// during materialization of large `WireArray(WireSubMsg)` payloads.
    #[test]
    fn audit_3_buffa_dynamic_enforces_max_alloc_bytes() {
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
}
