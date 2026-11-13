use std::collections::HashMap;

use omnibuf::opaque::{copy_packet, splice_fields};
use omnibuf::wire::{
    Decoder, Encoder, MAX_NESTING_DEPTH, WIRE_ARRAY, WIRE_BOOL_TRUE, WIRE_BYTES, WIRE_FIXED32,
    WIRE_FIXED64, WIRE_FLOAT32, WIRE_FLOAT64, WIRE_SFIXED32, WIRE_SFIXED64, WIRE_SINT, WIRE_STRING,
    WIRE_SUB_MSG, WIRE_UINT, append_tag, append_varint, counted_arr_len, decode_varint,
    decode_zigzag, encode_zigzag, locate_field, lookup_map_string_uint, read_bool, read_bytes,
    read_fixed32, read_fixed64, read_float32, read_float64, read_map_string_uint, read_sfixed32,
    read_sfixed64, read_sint, read_str, read_sub_msg, read_sub_msg_arr_elem, read_uint,
    sub_msg_arr_len,
};

#[test]
fn prefix_varint_boundaries_and_widths() {
    let cases: &[(u64, usize)] = &[
        (0, 1),
        (1, 1),
        (127, 1),
        (128, 2),
        (16_383, 2),
        (16_384, 4),
        (536_870_911, 4),
        (536_870_912, 9),
        (u64::from(u32::MAX), 9),
        (u64::MAX, 9),
    ];

    for &(val, expected_width) in cases {
        let mut buf = Vec::new();
        append_varint(&mut buf, val);
        assert_eq!(
            buf.len(),
            expected_width,
            "unexpected width for value {val}"
        );
        let (decoded, consumed) = decode_varint(&buf).expect("valid varint must decode");
        assert_eq!(decoded, val);
        assert_eq!(consumed, expected_width);

        // Any shorter slice must fail cleanly as truncated.
        for trunc in 0..expected_width {
            assert!(
                decode_varint(&buf[..trunc]).is_none(),
                "truncated slice of len {trunc} for {val} must return None"
            );
        }
    }
}

#[test]
fn prefix_varint_rejects_all_reserved_9byte_prefixes() {
    for high5 in 1u8..=31u8 {
        let b0 = high5 << 3;
        let mut raw = [0u8; 9];
        raw[0] = b0;
        assert!(
            decode_varint(&raw).is_none(),
            "reserved prefix 0x{b0:02x} must be rejected"
        );
    }
}

#[test]
fn zigzag_roundtrip_extremes() {
    let values = [
        0i64,
        -1,
        1,
        -2,
        2,
        i64::from(i32::MIN),
        i64::from(i32::MAX),
        i64::MIN + 1,
        i64::MIN,
        i64::MAX,
    ];
    for v in values {
        let encoded = encode_zigzag(v);
        assert_eq!(decode_zigzag(encoded), v);
    }
    assert_eq!(encode_zigzag(0), 0);
    assert_eq!(encode_zigzag(-1), 1);
    assert_eq!(encode_zigzag(1), 2);
    assert_eq!(encode_zigzag(-2), 3);
}

#[test]
fn encoder_decoder_scalars_and_random_access_readers() {
    let mut enc = Encoder::new(256);
    enc.write_uint(1, 424_242);
    enc.write_sint(2, -98_765);
    enc.write_bool(3, true);
    enc.write_bool(4, false);
    enc.write_fixed32(5, 0xDEAD_BEEF);
    enc.write_fixed64(6, 0x0102_0304_0506_0708);
    enc.write_sfixed32(7, -123_456);
    enc.write_sfixed64(8, -9_876_543_210);
    enc.write_float32(9, -0.0_f32);
    enc.write_float64(10, std::f64::consts::PI);
    enc.write_string(11, "Frankfurt-am-Main");
    enc.write_bytes(12, &[0xCA, 0xFE, 0xBA, 0xBE]);
    enc.write_string_arr(13, &["alpha", "beta", "gamma"]);
    enc.write_uint32_arr(14, &[10, 200, 30_000]);

    let mut map = HashMap::new();
    map.insert("rx_bytes".to_owned(), 1024u64);
    map.insert("tx_bytes".to_owned(), 2048u64);
    enc.write_map_string_uint(15, &map, true);

    let packet = enc.into_vec();

    assert_eq!(read_uint(&packet, 1), Some(424_242));
    assert_eq!(read_sint(&packet, 2), Some(-98_765));
    assert_eq!(read_bool(&packet, 3), Some(true));
    assert_eq!(read_bool(&packet, 4), Some(false));
    assert_eq!(read_fixed32(&packet, 5), Some(0xDEAD_BEEF));
    assert_eq!(read_fixed64(&packet, 6), Some(0x0102_0304_0506_0708));
    assert_eq!(read_sfixed32(&packet, 7), Some(-123_456));
    assert_eq!(read_sfixed64(&packet, 8), Some(-9_876_543_210));
    assert_eq!(
        read_float32(&packet, 9).map(f32::to_bits),
        Some((-0.0_f32).to_bits())
    );
    assert_eq!(read_float64(&packet, 10), Some(std::f64::consts::PI));
    assert_eq!(read_str(&packet, 11), Some("Frankfurt-am-Main"));
    assert_eq!(read_bytes(&packet, 12), Some(&[0xCA, 0xFE, 0xBA, 0xBE][..]));
    assert_eq!(counted_arr_len(&packet, 13, WIRE_STRING), 3);
    assert_eq!(counted_arr_len(&packet, 14, WIRE_UINT), 3);
    assert_eq!(lookup_map_string_uint(&packet, 15, "rx_bytes"), Some(1024));
    assert_eq!(lookup_map_string_uint(&packet, 15, "tx_bytes"), Some(2048));
    assert_eq!(lookup_map_string_uint(&packet, 15, "missing"), None);
    assert_eq!(read_map_string_uint(&packet, 15), Some(map));

    // Verify streaming Decoder reads the exact wire types in sequence.
    let mut dec = Decoder::new(&packet);
    assert_eq!(dec.next_tag().unwrap(), Some((1, WIRE_UINT)));
    assert_eq!(dec.read_uint().unwrap(), 424_242);
    assert_eq!(dec.next_tag().unwrap(), Some((2, WIRE_SINT)));
    assert_eq!(dec.read_sint().unwrap(), -98_765);
    assert_eq!(dec.next_tag().unwrap(), Some((3, WIRE_BOOL_TRUE)));
    let _ = dec.next_tag().unwrap();
    assert_eq!(dec.next_tag().unwrap(), Some((5, WIRE_FIXED32)));
    assert_eq!(dec.read_fixed32().unwrap(), 0xDEAD_BEEF);
    assert_eq!(dec.next_tag().unwrap(), Some((6, WIRE_FIXED64)));
    assert_eq!(dec.read_fixed64().unwrap(), 0x0102_0304_0506_0708);
    assert_eq!(dec.next_tag().unwrap(), Some((7, WIRE_SFIXED32)));
    assert_eq!(dec.read_sfixed32().unwrap(), -123_456);
    assert_eq!(dec.next_tag().unwrap(), Some((8, WIRE_SFIXED64)));
    assert_eq!(dec.read_sfixed64().unwrap(), -9_876_543_210);
    assert_eq!(dec.next_tag().unwrap(), Some((9, WIRE_FLOAT32)));
    assert_eq!(dec.read_float32().unwrap().to_bits(), (-0.0_f32).to_bits());
    assert_eq!(dec.next_tag().unwrap(), Some((10, WIRE_FLOAT64)));
    assert_eq!(dec.read_float64().unwrap(), std::f64::consts::PI);
    assert_eq!(dec.next_tag().unwrap(), Some((11, WIRE_STRING)));
    assert_eq!(dec.read_str().unwrap(), "Frankfurt-am-Main");
    assert_eq!(dec.next_tag().unwrap(), Some((12, WIRE_BYTES)));
    assert_eq!(dec.read_bytes().unwrap(), &[0xCA, 0xFE, 0xBA, 0xBE]);
    while let Some((fnum, wt)) = dec.next_tag().unwrap() {
        dec.skip_unknown(fnum, wt).unwrap();
    }
    assert!(dec.is_empty());
}

#[test]
fn large_container_backpatch_and_200_submsg_array_count_patch() {
    let mut enc = Encoder::default();

    // 1. Sub-message larger than 16,383 bytes triggers 2B -> 4B length header expansion.
    let big_payload = vec![0xABu8; 20_000];
    enc.begin_sub_msg(1);
    enc.write_bytes(1, &big_payload);
    enc.end_sub_msg();

    // 2. Sub-message array with 200 items triggers 1B -> 2B reserved count expansion.
    enc.begin_sub_msg_arr(2);
    for idx in 0..200u64 {
        enc.begin_sub_msg_elem();
        enc.write_uint(1, idx * 3);
        enc.end_sub_msg_elem();
    }
    enc.end_sub_msg_arr();

    let packet = enc.into_vec();

    let sub = read_sub_msg(&packet, 1).expect("large sub-message must be readable");
    assert_eq!(read_bytes(&sub, 1), Some(big_payload.as_slice()));

    assert_eq!(sub_msg_arr_len(&packet, 2), 200);
    for idx in [0usize, 1, 127, 128, 199] {
        let elem = read_sub_msg_arr_elem(&packet, 2, idx).expect("element must exist");
        assert_eq!(read_uint(elem, 1), Some((idx as u64) * 3));
    }
    assert!(read_sub_msg_arr_elem(&packet, 2, 200).is_none());

    // Verify WireArray header is locatable via locate_field.
    let (_, wt) = locate_field(&packet, 2).expect("field 2 must exist");
    assert_eq!(wt, WIRE_ARRAY);
}

#[test]
fn encoder_overflow_stack_and_depth_limit() {
    // Push 70 nested sub-messages on Encoder to exercise dynamic stack growth beyond 64 inline slots.
    let mut enc = Encoder::default();
    for _ in 0..70 {
        enc.begin_sub_msg(1);
    }
    enc.write_uint(7, 999);
    for _ in 0..70 {
        enc.end_sub_msg();
    }
    let deep_packet = enc.into_vec();

    // Decoding at depth > MAX_NESTING_DEPTH (32) must return DepthLimitExceeded.
    let mut dec = Decoder::new(&deep_packet);
    let (fnum, wt) = dec.next_tag().unwrap().unwrap();
    assert_eq!((fnum, wt), (1, WIRE_SUB_MSG));
    let err = dec.skip_unknown(fnum, wt).unwrap_err();
    assert!(matches!(err, omnibuf::Error::DepthLimitExceeded(_)));
    assert!(Decoder::with_depth(&[], MAX_NESTING_DEPTH).is_ok());
    assert!(matches!(
        Decoder::with_depth(&[], MAX_NESTING_DEPTH + 1),
        Err(omnibuf::Error::DepthLimitExceeded(_))
    ));
}

#[test]
fn opaque_splice_grow_shrink_delete_append_and_prefix_preservation() {
    let mut enc = Encoder::default();
    enc.write_uint(1, 10);
    enc.write_string(2, "short");
    enc.write_uint(3, 30);
    // Duplicate field 2 (last-value-wins on wire; splice deduplicates when dirty).
    enc.write_string(2, "override");
    let raw = enc.into_vec();

    // 1. Prefix preservation + grow field 2 + append new field 5.
    let mut dst = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let dirty_grow = (1u64 << 2) | (1u64 << 5);
    splice_fields(&mut dst, &raw, dirty_grow, 5, |out, fnum| match fnum {
        2 => {
            append_tag(out, 2, WIRE_STRING);
            let long_str = "a-much-longer-replacement-router-hostname";
            append_varint(out, long_str.len() as u64);
            out.extend_from_slice(long_str.as_bytes());
        }
        5 => {
            append_tag(out, 5, WIRE_UINT);
            append_varint(out, 555);
        }
        _ => {}
    });
    assert_eq!(&dst[..4], &[0xDE, 0xAD, 0xBE, 0xEF]);
    let spliced = &dst[4..];
    assert_eq!(read_uint(spliced, 1), Some(10));
    assert_eq!(
        read_str(spliced, 2),
        Some("a-much-longer-replacement-router-hostname")
    );
    assert_eq!(read_uint(spliced, 3), Some(30));
    assert_eq!(read_uint(spliced, 5), Some(555));

    // 2. Delete field 2 (emit nothing in closure when dirty bit 2 is set).
    let mut deleted = Vec::new();
    splice_fields(&mut deleted, spliced, 1u64 << 2, 5, |_out, _fnum| {});
    assert_eq!(read_str(&deleted, 2), None);
    assert_eq!(read_uint(&deleted, 1), Some(10));
    assert_eq!(read_uint(&deleted, 3), Some(30));
    assert_eq!(read_uint(&deleted, 5), Some(555));

    // 3. Truncated tail stops cleanly instead of copying corrupt bytes.
    let mut corrupt = raw.clone();
    corrupt.push(0x2A); // Truncated 2-byte tag at tail
    let mut cleaned = Vec::new();
    splice_fields(&mut cleaned, &corrupt, 1u64 << 1, 3, |out, fnum| {
        if fnum == 1 {
            append_tag(out, 1, WIRE_UINT);
            append_varint(out, 99);
        }
    });
    assert_eq!(read_uint(&cleaned, 1), Some(99));
    assert_eq!(read_str(&cleaned, 2), Some("override"));

    // 4. copy_packet replaces dst with raw cleanly.
    let mut framed = vec![0xAA];
    copy_packet(&mut framed, &cleaned);
    assert_eq!(framed.as_slice(), cleaned.as_slice());
}
