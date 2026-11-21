#![cfg(feature = "derive")]

use std::collections::HashMap;

use omnibuf::wire::{Encoder, WIRE_STRING, append_bytes_elem, append_tag};
use omnibuf::{DecodeBorrowed, Message, OmniBuf, from_slice_borrowed, to_vec_deterministic};

#[path = "../../conformance-rs/src/generated/omnibuf/bench/peer_omnibuf.rs"]
mod peer_omnibuf;

#[path = "../../conformance-rs/src/generated/omnibuf/conformance/conformance_omnibuf.rs"]
mod all_types_omnibuf;

fn assert_borrows_from(slice_ptr: *const u8, slice_len: usize, buf: &[u8], label: &str) {
    assert!(slice_len > 0, "{label}: expected non-empty slice");
    let buf_start = buf.as_ptr() as usize;
    let buf_end = buf_start + buf.len();
    let ptr = slice_ptr as usize;
    assert!(
        ptr >= buf_start && ptr + slice_len <= buf_end,
        "{label}: pointer 0x{ptr:x}..0x{:x} does not borrow from input buffer 0x{buf_start:x}..0x{buf_end:x}",
        ptr + slice_len
    );
}

#[test]
fn borrowed_decode_zero_copy_address_borrowing() {
    let orig = all_types_omnibuf::TestAllTypes {
        f1_uint32: 42,
        f2_uint64: 9_000_000_000,
        f3_sint32: -123,
        f4_sint64: -987_654_321,
        f5_bool: true,
        f6_string: "zero-copy-top-level-string-payload".to_owned(),
        f7_bytes: b"zero-copy-raw-bytes-payload".to_vec(),
        f8_sub_msg: Some(all_types_omnibuf::AllTypesSubMsg {
            id: 77,
            label: "nested-sub-msg-label".to_owned(),
            flag: true,
            score: -55,
        }),
        f9_string_arr: vec!["arr-alpha".to_owned(), "arr-beta-longer".to_owned()],
        f10_uint32_arr: vec![1, 2, 3, 4],
        f11_sub_msg_arr: vec![
            all_types_omnibuf::AllTypesSubMsg {
                id: 1,
                label: "elem-zero-label".to_owned(),
                flag: false,
                score: 10,
            },
            all_types_omnibuf::AllTypesSubMsg {
                id: 2,
                label: "elem-one-label".to_owned(),
                flag: true,
                score: -20,
            },
        ],
        f12_map_str_uint: HashMap::from([
            ("map-key-alpha".to_owned(), 100),
            ("map-key-beta".to_owned(), 200),
        ]),
        f13_float32: 3.5,
        f14_float64: -6.25,
        f15_fixed32: 0x1122_3344,
        f16_fixed64: 0x0102_0304_0506_0708,
        f20_overflow_str: "overflow-borrowed-string".to_owned(),
    };

    let raw = orig.marshal_omnibuf();
    let borrowed: all_types_omnibuf::TestAllTypesBorrowed<'_> =
        from_slice_borrowed(&raw).expect("borrowed decode failed");

    assert_eq!(borrowed.f1_uint32, orig.f1_uint32);
    assert_eq!(borrowed.f2_uint64, orig.f2_uint64);
    assert_eq!(borrowed.f3_sint32, orig.f3_sint32);
    assert_eq!(borrowed.f4_sint64, orig.f4_sint64);
    assert_eq!(borrowed.f5_bool, orig.f5_bool);
    assert_eq!(borrowed.f6_string, orig.f6_string);
    assert_eq!(borrowed.f7_bytes, orig.f7_bytes.as_slice());
    assert_eq!(borrowed.f9_string_arr, vec!["arr-alpha", "arr-beta-longer"]);
    assert_eq!(borrowed.f10_uint32_arr, orig.f10_uint32_arr);
    assert_eq!(borrowed.f11_sub_msg_arr.len(), 2);
    assert_eq!(borrowed.f11_sub_msg_arr[0].label, "elem-zero-label");
    assert_eq!(borrowed.f11_sub_msg_arr[1].label, "elem-one-label");
    assert_eq!(borrowed.f12_map_str_uint.get("map-key-alpha"), Some(&100));
    assert_eq!(borrowed.f12_map_str_uint.get("map-key-beta"), Some(&200));
    assert_eq!(borrowed.f20_overflow_str, orig.f20_overflow_str);

    // Verify every borrowed string and byte slice points directly into `raw`
    assert_borrows_from(
        borrowed.f6_string.as_ptr(),
        borrowed.f6_string.len(),
        &raw,
        "f6_string",
    );
    assert_borrows_from(
        borrowed.f7_bytes.as_ptr(),
        borrowed.f7_bytes.len(),
        &raw,
        "f7_bytes",
    );
    let sub = borrowed.f8_sub_msg.as_ref().expect("f8_sub_msg missing");
    assert_borrows_from(
        sub.label.as_ptr(),
        sub.label.len(),
        &raw,
        "f8_sub_msg.label",
    );
    for (i, s) in borrowed.f9_string_arr.iter().enumerate() {
        assert_borrows_from(s.as_ptr(), s.len(), &raw, &format!("f9_string_arr[{i}]"));
    }
    for (i, item) in borrowed.f11_sub_msg_arr.iter().enumerate() {
        assert_borrows_from(
            item.label.as_ptr(),
            item.label.len(),
            &raw,
            &format!("f11_sub_msg_arr[{i}].label"),
        );
    }
    for key in borrowed.f12_map_str_uint.keys() {
        assert_borrows_from(key.as_ptr(), key.len(), &raw, "f12_map_str_uint key");
    }
    assert_borrows_from(
        borrowed.f20_overflow_str.as_ptr(),
        borrowed.f20_overflow_str.len(),
        &raw,
        "f20_overflow_str",
    );

    // Verify reuse via `unmarshal_omnibuf` clears stale fields
    let mut reused = borrowed;
    let empty: &[u8] = &[];
    reused.decode_omnibuf_borrowed(empty).unwrap();
    assert!(reused.f6_string.is_empty());
    assert!(reused.f7_bytes.is_empty());
    assert!(reused.f8_sub_msg.is_none());
    assert!(reused.f9_string_arr.is_empty());
    assert!(reused.f11_sub_msg_arr.is_empty());
    assert!(reused.f12_map_str_uint.is_empty());
}

#[test]
fn opaque_boxed_dirty_lazy_dir_linear_iter_and_marshal_validated() {
    // Compact stack size thanks to boxed lazy dirty state
    assert!(
        core::mem::size_of::<peer_omnibuf::OpaquePeerUpdate<'_>>() <= 64,
        "OpaquePeerUpdate stack size regressed: {} bytes",
        core::mem::size_of::<peer_omnibuf::OpaquePeerUpdate<'_>>()
    );
    assert!(
        core::mem::size_of::<all_types_omnibuf::OpaqueTestAllTypes<'_>>() <= 64,
        "OpaqueTestAllTypes stack size regressed: {} bytes",
        core::mem::size_of::<all_types_omnibuf::OpaqueTestAllTypes<'_>>()
    );

    let orig = all_types_omnibuf::TestAllTypes {
        f1_uint32: 11,
        f2_uint64: 22,
        f3_sint32: -33,
        f4_sint64: -44,
        f5_bool: true,
        f6_string: "hello-lazy-dir".to_owned(),
        f7_bytes: vec![1, 2, 3],
        f8_sub_msg: Some(all_types_omnibuf::AllTypesSubMsg {
            id: 9,
            label: "sub".to_owned(),
            flag: true,
            score: 5,
        }),
        f11_sub_msg_arr: (0..25)
            .map(|i| all_types_omnibuf::AllTypesSubMsg {
                id: i,
                label: format!("node-{i}"),
                flag: i % 2 == 0,
                score: -(i as i64),
            })
            .collect(),
        ..Default::default()
    };
    let raw = orig.marshal_omnibuf();
    let mut view = all_types_omnibuf::OpaqueTestAllTypes::new(&raw);

    // 3+ reads activate the lazy FieldDir cache
    assert_eq!(view.get_f1_uint32(), 11);
    assert_eq!(view.get_f2_uint64(), 22);
    assert_eq!(view.get_f3_sint32(), -33);
    assert_eq!(view.get_f4_sint64(), -44);
    assert!(view.get_f5_bool());
    assert_eq!(view.get_f6_string(), "hello-lazy-dir");
    assert_eq!(view.get_f7_bytes(), &[1, 2, 3]);
    assert!(view.has_f8_sub_msg());
    assert_eq!(view.get_f8_sub_msg().get_label(), "sub");

    // Linear O(M) iterator in clean state
    let clean_iter = view.iter_f11_sub_msg_arr();
    assert_eq!(clean_iter.len(), 25);
    for (idx, item) in clean_iter.enumerate() {
        assert_eq!(item.get_id(), idx as u32);
        assert_eq!(item.get_label(), format!("node-{idx}"));
    }

    // Linear O(M) iterator in dirty state
    view.set_f11_sub_msg_arr(vec![all_types_omnibuf::AllTypesSubMsg {
        id: 777,
        label: "dirty-item".to_owned(),
        flag: true,
        score: 99,
    }]);
    let dirty_iter = view.iter_f11_sub_msg_arr();
    assert_eq!(dirty_iter.len(), 1);
    let collected: Vec<u32> = dirty_iter.map(|e| e.get_id()).collect();
    assert_eq!(collected, vec![777]);

    // marshal_validated rejects invalid UTF-8 inside an untouched unknown WireString field
    let mut bad_pkt = raw.clone();
    append_tag(&mut bad_pkt, 99, WIRE_STRING);
    append_bytes_elem(&mut bad_pkt, &[0xFF, 0xFE, 0xFD]);
    let mut bad_view = all_types_omnibuf::OpaqueTestAllTypes::new(&bad_pkt);
    bad_view.set_f1_uint32(55);
    assert!(
        bad_view.marshal_validated().is_err(),
        "marshal_validated must reject invalid UTF-8 in untouched unknown WireString field"
    );
}

#[derive(Clone, Debug, Default, PartialEq, OmniBuf)]
struct DeriveLargeSub {
    #[omnibuf(id = 1)]
    id: u32,
    #[omnibuf(id = 2)]
    label: String,
    #[omnibuf(id = 3)]
    flag: bool,
    #[omnibuf(id = 4, wire = "sint")]
    score: i64,
}

#[derive(Clone, Debug, Default, PartialEq, OmniBuf)]
struct DeriveLargeOuter {
    #[omnibuf(id = 8)]
    sub: Option<DeriveLargeSub>,
    #[omnibuf(id = 11)]
    items: Vec<DeriveLargeSub>,
}

#[test]
fn large_container_over_16kib_backpatch_bit_exact_equivalence() {
    let big_label = "A".repeat(20_000);
    assert!(big_label.len() > 16_383);

    // 1. Plugin-generated struct
    let plugin_msg = all_types_omnibuf::TestAllTypes {
        f8_sub_msg: Some(all_types_omnibuf::AllTypesSubMsg {
            id: 1,
            label: big_label.clone(),
            flag: true,
            score: -42,
        }),
        f11_sub_msg_arr: vec![
            all_types_omnibuf::AllTypesSubMsg {
                id: 2,
                label: big_label.clone(),
                flag: false,
                score: 100,
            },
            all_types_omnibuf::AllTypesSubMsg {
                id: 3,
                label: "small".to_owned(),
                flag: true,
                score: 0,
            },
        ],
        ..Default::default()
    };
    assert!(plugin_msg.min_wire_size() > 16_383);

    // 2. Derive struct (same field numbers & values on fields 8 and 11)
    let derive_msg = DeriveLargeOuter {
        sub: Some(DeriveLargeSub {
            id: 1,
            label: big_label.clone(),
            flag: true,
            score: -42,
        }),
        items: vec![
            DeriveLargeSub {
                id: 2,
                label: big_label.clone(),
                flag: false,
                score: 100,
            },
            DeriveLargeSub {
                id: 3,
                label: "small".to_owned(),
                flag: true,
                score: 0,
            },
        ],
    };
    assert!(derive_msg.min_wire_size() > 16_383);
    let pkt_derive = to_vec_deterministic(&derive_msg).unwrap();

    // 3. Manual Encoder
    let mut enc = Encoder::default();
    enc.begin_sub_msg(8);
    enc.write_uint(1, 1);
    enc.write_string(2, &big_label);
    enc.write_bool(3, true);
    enc.write_sint(4, -42);
    enc.end_sub_msg();
    enc.begin_sub_msg_arr(11);
    enc.begin_sub_msg_elem();
    enc.write_uint(1, 2);
    enc.write_string(2, &big_label);
    enc.write_bool(3, false);
    enc.write_sint(4, 100);
    enc.end_sub_msg_elem();
    enc.begin_sub_msg_elem();
    enc.write_uint(1, 3);
    enc.write_string(2, "small");
    enc.write_bool(3, true);
    enc.write_sint(4, 0);
    enc.end_sub_msg_elem();
    enc.end_sub_msg_arr();
    let pkt_enc = enc.into_vec();

    // Exact bit-for-bit equivalence between Encoder and Derive on >16 KiB containers
    assert_eq!(pkt_enc, pkt_derive);

    // Decode pkt_enc with plugin-generated TestAllTypes and TestAllTypesBorrowed
    let decoded_plugin = all_types_omnibuf::TestAllTypes::from_omnibuf(&pkt_enc).unwrap();
    assert_eq!(decoded_plugin.f8_sub_msg, plugin_msg.f8_sub_msg);
    assert_eq!(decoded_plugin.f11_sub_msg_arr, plugin_msg.f11_sub_msg_arr);

    let decoded_borrowed: all_types_omnibuf::TestAllTypesBorrowed<'_> =
        from_slice_borrowed(&pkt_enc).unwrap();
    assert_eq!(
        decoded_borrowed.f8_sub_msg.as_ref().unwrap().label,
        big_label
    );
    assert_borrows_from(
        decoded_borrowed.f8_sub_msg.as_ref().unwrap().label.as_ptr(),
        big_label.len(),
        &pkt_enc,
        ">16 KiB f8_sub_msg.label",
    );
}
