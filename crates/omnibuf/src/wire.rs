use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};

use crate::error::{Error, Result};
use crate::field0::{validate_field0, validate_field0_with_max_depth};

/// Unsigned integer (`[Prefix-Varint]`).
pub const WIRE_UINT: u8 = 0;
/// ZigZag-encoded signed integer (`[Prefix-Varint]`).
pub const WIRE_SINT: u8 = 1;
/// Boolean `false` in field tags (0 payload bytes), or 1-byte boolean descriptor in `WireArray`/`WireMap`.
pub const WIRE_BOOL_FALSE: u8 = 2;
/// Boolean `true` in field tags (0 payload bytes). Invalid inside `WireArray`/`WireMap` headers.
pub const WIRE_BOOL_TRUE: u8 = 3;
/// 4-byte little-endian unsigned 32-bit integer.
pub const WIRE_FIXED32: u8 = 4;
/// 8-byte little-endian unsigned 64-bit integer.
pub const WIRE_FIXED64: u8 = 5;
/// 4-byte little-endian signed 32-bit integer.
pub const WIRE_SFIXED32: u8 = 6;
/// 8-byte little-endian signed 64-bit integer.
pub const WIRE_SFIXED64: u8 = 7;
/// 4-byte little-endian IEEE-754 `f32`.
pub const WIRE_FLOAT32: u8 = 8;
/// 8-byte little-endian IEEE-754 `f64`.
pub const WIRE_FLOAT64: u8 = 9;
/// Length-prefixed UTF-8 string (`[ByteLen][UTF-8 Bytes]`).
pub const WIRE_STRING: u8 = 10;
/// Length-prefixed raw byte slice (`[ByteLen][Raw Bytes]`).
pub const WIRE_BYTES: u8 = 11;
/// Length-prefixed nested sub-message (`[ByteLen][Sub-Packet Bytes]`).
pub const WIRE_SUB_MSG: u8 = 12;
/// Length-prefixed typed array (`[ByteLen][ElemType: 1B][Count: Prefix-Varint][Elements...]`).
pub const WIRE_ARRAY: u8 = 13;
/// Length-prefixed typed map (`[ByteLen][KeyType: 1B][ValType: 1B][Count: Prefix-Varint][Entries...]`).
pub const WIRE_MAP: u8 = 14;
/// Length-prefixed future extension (`[ByteLen][ExtType: 1B][Payload...]`).
pub const WIRE_EXTENDED: u8 = 15;

/// Maximum allowed container and sub-message recursion depth.
pub const MAX_NESTING_DEPTH: usize = 32;

/// Maximum allowed 29-bit field number (`(1 << 29) - 1`).
pub const MAX_FIELD_NUMBER: u64 = 536_870_911;

const INLINE_STACK_SLOTS: usize = MAX_NESTING_DEPTH * 2;

/// Maps a signed `i64` to an unsigned `u64` using ZigZag encoding.
#[inline]
pub const fn encode_zigzag(n: i64) -> u64 {
    ((n << 1) ^ (n >> 63)) as u64
}

/// Maps a ZigZag-encoded `u64` back to a signed `i64`.
#[inline]
pub const fn decode_zigzag(u: u64) -> i64 {
    ((u >> 1) as i64) ^ -((u & 1) as i64)
}

/// Returns the encoded byte width (1, 2, 4, or 9) of `v` as a Prefix-Varint.
#[inline(always)]
pub const fn varint_len(v: u64) -> usize {
    if v <= 127 {
        1
    } else if v <= 16_383 {
        2
    } else if v <= 536_870_911 {
        4
    } else {
        9
    }
}

/// Returns the canonical container length header width (2, 4, or 9 bytes) for `sub_len`.
#[inline(always)]
pub const fn container_len_width(sub_len: usize) -> usize {
    if sub_len <= 16_383 {
        2
    } else if sub_len <= 536_870_911 {
        4
    } else {
        9
    }
}

/// Encodes `v` as a Prefix-Varint directly at `ptr`, returning the byte width (1, 2, 4, or 9).
///
/// # Safety
/// `ptr` must be valid for writes of at least 9 bytes.
#[inline(always)]
pub(crate) unsafe fn put_varint_raw(ptr: *mut u8, v: u64) -> usize {
    unsafe {
        if v <= 127 {
            *ptr = ((v as u8) << 1) | 1;
            1
        } else if v <= 16_383 {
            let u = ((v as u16) << 2) | 2;
            core::ptr::copy_nonoverlapping(u.to_le_bytes().as_ptr(), ptr, 2);
            2
        } else if v <= 536_870_911 {
            let u = ((v as u32) << 3) | 4;
            core::ptr::copy_nonoverlapping(u.to_le_bytes().as_ptr(), ptr, 4);
            4
        } else {
            *ptr = 0x00;
            core::ptr::copy_nonoverlapping(v.to_le_bytes().as_ptr(), ptr.add(1), 8);
            9
        }
    }
}

/// Appends a Prefix-Varint to `dst`.
#[inline(always)]
pub fn append_varint(dst: &mut Vec<u8>, v: u64) {
    dst.reserve(9);
    unsafe {
        let len = dst.len();
        let vn = put_varint_raw(dst.as_mut_ptr().add(len), v);
        dst.set_len(len + vn);
    }
}

/// Appends a field tag `(field_num << 4) | wire_type` as a Prefix-Varint.
#[inline(always)]
pub fn append_tag(dst: &mut Vec<u8>, field_num: u32, wire_type: u8) {
    let tag = (u64::from(field_num) << 4) | u64::from(wire_type & 0x0F);
    append_varint(dst, tag);
}

/// Appends a pre-encoded tag followed by a Prefix-Varint payload in a single capacity check.
#[inline(always)]
pub fn write_varint_tagged<const N: usize>(dst: &mut Vec<u8>, tag: [u8; N], v: u64) {
    const {
        assert!(N <= 16);
    }
    dst.reserve(N + 9);
    unsafe {
        let len = dst.len();
        let ptr = dst.as_mut_ptr().add(len);
        core::ptr::copy_nonoverlapping(tag.as_ptr(), ptr, N);
        let vn = put_varint_raw(ptr.add(N), v);
        dst.set_len(len + N + vn);
    }
}

/// Appends a pre-encoded boolean tag (`tag_false` or `tag_true`).
#[inline(always)]
pub fn write_bool_tagged<const N: usize>(
    dst: &mut Vec<u8>,
    tag_false: [u8; N],
    tag_true: [u8; N],
    v: bool,
) {
    const {
        assert!(N <= 16);
    }
    let tag = if v { tag_true } else { tag_false };
    dst.extend_from_slice(&tag);
}

/// Appends a pre-encoded tag followed by a fixed-width little-endian payload in a single capacity check.
#[inline(always)]
pub fn write_fixed_tagged<const N: usize, const W: usize>(
    dst: &mut Vec<u8>,
    tag: [u8; N],
    val: [u8; W],
) {
    const {
        assert!(N <= 16 && W <= 16);
    }
    dst.reserve(N + W);
    unsafe {
        let len = dst.len();
        let ptr = dst.as_mut_ptr().add(len);
        core::ptr::copy_nonoverlapping(tag.as_ptr(), ptr, N);
        core::ptr::copy_nonoverlapping(val.as_ptr(), ptr.add(N), W);
        dst.set_len(len + N + W);
    }
}

/// Appends a pre-encoded tag followed by a length-prefixed byte or UTF-8 slice in a single capacity check.
#[inline(always)]
pub fn write_bytes_tagged<const N: usize>(dst: &mut Vec<u8>, tag: [u8; N], b: &[u8]) {
    const {
        assert!(N <= 16);
    }
    let blen = b.len();
    let needed = blen.checked_add(N + 9).expect("capacity overflow");
    dst.reserve(needed);
    unsafe {
        let len = dst.len();
        let ptr = dst.as_mut_ptr().add(len);
        core::ptr::copy_nonoverlapping(tag.as_ptr(), ptr, N);
        let vn = put_varint_raw(ptr.add(N), blen as u64);
        core::ptr::copy_nonoverlapping(b.as_ptr(), ptr.add(N + vn), blen);
        dst.set_len(len + N + vn + blen);
    }
}

/// Appends an untagged length-prefixed byte or UTF-8 slice in a single capacity check.
#[inline(always)]
pub fn append_bytes_elem(dst: &mut Vec<u8>, b: &[u8]) {
    let blen = b.len();
    let needed = blen.checked_add(9).expect("capacity overflow");
    dst.reserve(needed);
    unsafe {
        let len = dst.len();
        let ptr = dst.as_mut_ptr().add(len);
        let vn = put_varint_raw(ptr, blen as u64);
        core::ptr::copy_nonoverlapping(b.as_ptr(), ptr.add(vn), blen);
        dst.set_len(len + vn + blen);
    }
}

/// Decodes a Prefix-Varint from `b` using `u8::trailing_zeros()` (`TZCNT` / `CTZ`).
///
/// Returns `Some((value, bytes_read))` on valid input, or `None` if `b` is empty,
/// truncated, or begins with a reserved non-zero 9-byte marker (`b0 & 0x07 == 0 && b0 != 0`).
#[inline]
pub fn decode_varint(b: &[u8]) -> Option<(u64, usize)> {
    let b0 = *b.first()?;
    match b0.trailing_zeros() {
        0 => Some((u64::from(b0 >> 1), 1)),
        1 => {
            let raw: [u8; 2] = b.get(..2)?.try_into().ok()?;
            Some((u64::from(u16::from_le_bytes(raw) >> 2), 2))
        }
        2 => {
            let raw: [u8; 4] = b.get(..4)?.try_into().ok()?;
            Some((u64::from(u32::from_le_bytes(raw) >> 3), 4))
        }
        8 => {
            let raw: [u8; 8] = b.get(1..9)?.try_into().ok()?;
            Some((u64::from_le_bytes(raw), 9))
        }
        _ => None,
    }
}

/// Encodes `v` (`0..=16383`) as an explicit 2-byte Prefix-Varint at `dst[..2]`.
#[inline]
pub fn put_overlong_2b_varint(dst: &mut [u8], v: u16) {
    assert!(
        dst.len() >= 2 && v <= 16_383,
        "put_overlong_2b_varint requires dst.len() >= 2 and v <= 16383"
    );
    let encoded = (v << 2) | 2;
    dst[..2].copy_from_slice(&encoded.to_le_bytes());
}

/// Backpatches the container byte length reserved at `dst[len_pos..len_pos + 2]`.
///
/// Payloads up to `16_383` bytes patch in place; larger payloads expand the length
/// header to 4 or 9 bytes by shifting the container body forward.
#[inline(always)]
pub fn backpatch_container_len(dst: &mut Vec<u8>, len_pos: usize) {
    let Some(header_end) = len_pos.checked_add(2) else {
        return;
    };
    let Some(sub_len) = dst.len().checked_sub(header_end) else {
        return;
    };
    if sub_len <= 16_383 {
        let u = ((sub_len as u16) << 2) | 2;
        dst[len_pos..header_end].copy_from_slice(&u.to_le_bytes());
    } else {
        backpatch_large_container_len(dst, len_pos, sub_len);
    }
}

#[cold]
#[inline(never)]
fn backpatch_large_container_len(dst: &mut Vec<u8>, len_pos: usize, sub_len: usize) {
    let old_len = dst.len();
    if sub_len <= 536_870_911 {
        dst.resize(old_len + 2, 0);
        dst.copy_within(len_pos + 2..old_len, len_pos + 4);
        let u = ((sub_len as u32) << 3) | 4;
        dst[len_pos..len_pos + 4].copy_from_slice(&u.to_le_bytes());
    } else {
        dst.resize(old_len + 7, 0);
        dst.copy_within(len_pos + 2..old_len, len_pos + 9);
        dst[len_pos] = 0;
        let bytes = (sub_len as u64).to_le_bytes();
        dst[len_pos + 1..len_pos + 9].copy_from_slice(&bytes);
    }
}

/// Backpatches a 4-byte container length slot reserved at `dst[len_pos..len_pos + 4]`.
///
/// Payloads in `16_384..=536_870_911` patch in place without shifting; smaller payloads
/// compact back to the canonical 2-byte header and larger payloads expand to 9 bytes.
#[inline(always)]
pub fn backpatch_container_len_4b(dst: &mut Vec<u8>, len_pos: usize) {
    let Some(header_end) = len_pos.checked_add(4) else {
        return;
    };
    let Some(sub_len) = dst.len().checked_sub(header_end) else {
        return;
    };
    if (16_384..=536_870_911).contains(&sub_len) {
        let u = ((sub_len as u32) << 3) | 4;
        dst[len_pos..header_end].copy_from_slice(&u.to_le_bytes());
    } else {
        backpatch_container_len_4b_adjust(dst, len_pos, sub_len);
    }
}

#[cold]
#[inline(never)]
fn backpatch_container_len_4b_adjust(dst: &mut Vec<u8>, len_pos: usize, sub_len: usize) {
    let old_len = dst.len();
    if sub_len <= 16_383 {
        dst.copy_within(len_pos + 4..old_len, len_pos + 2);
        dst.truncate(old_len - 2);
        let u = ((sub_len as u16) << 2) | 2;
        dst[len_pos..len_pos + 2].copy_from_slice(&u.to_le_bytes());
    } else {
        dst.resize(old_len + 5, 0);
        dst.copy_within(len_pos + 4..old_len, len_pos + 9);
        dst[len_pos] = 0;
        let bytes = (sub_len as u64).to_le_bytes();
        dst[len_pos + 1..len_pos + 9].copy_from_slice(&bytes);
    }
}

/// Fills a 1-byte reserved varint slot at `dst[pos]` and expands it if `value > 127`.
#[inline]
pub fn patch_reserved_varint(dst: &mut Vec<u8>, pos: usize, value: u64) {
    assert!(pos < dst.len(), "patch_reserved_varint pos out of bounds");
    if value <= 127 {
        dst[pos] = ((value as u8) << 1) | 1;
        return;
    }
    let width = if value > 536_870_911 {
        9
    } else if value > 16_383 {
        4
    } else {
        2
    };
    let old_len = dst.len();
    dst.resize(old_len + (width - 1), 0);
    dst.copy_within(pos + 1..old_len, pos + width);
    match width {
        2 => {
            let u = ((value as u16) << 2) | 2;
            dst[pos..pos + 2].copy_from_slice(&u.to_le_bytes());
        }
        4 => {
            let u = ((value as u32) << 3) | 4;
            dst[pos..pos + 4].copy_from_slice(&u.to_le_bytes());
        }
        _ => {
            dst[pos] = 0;
            dst[pos + 1..pos + 9].copy_from_slice(&value.to_le_bytes());
        }
    }
}

/// Computes amortized capacity for repeated field decoding so fragmented packets stay linear.
#[inline]
pub fn grow_capacity(current: usize, required: usize) -> usize {
    if let Some(doubled) = current.checked_mul(2)
        && doubled > required
    {
        return doubled;
    }
    required
}

/// Checks whether `b` is valid UTF-8 with an unrestricted word-scan fast path for ASCII strings.
#[inline(always)]
pub fn validate_utf8(b: &[u8]) -> Result<&str> {
    let n = b.len();
    if n == 0 {
        return Ok("");
    }
    if n <= 16 {
        if n >= 8 {
            let lo = u64::from_le_bytes(b[..8].try_into().unwrap());
            let hi = u64::from_le_bytes(b[n - 8..n].try_into().unwrap());
            if ((lo | hi) & 0x8080_8080_8080_8080) == 0 {
                // SAFETY: Every byte has its high bit clear (0x00..=0x7F), which is valid ASCII/UTF-8.
                return Ok(unsafe { core::str::from_utf8_unchecked(b) });
            }
        } else if n >= 4 {
            let lo = u32::from_le_bytes(b[..4].try_into().unwrap());
            let hi = u32::from_le_bytes(b[n - 4..n].try_into().unwrap());
            if ((lo | hi) & 0x8080_8080) == 0 {
                // SAFETY: Every byte has its high bit clear (0x00..=0x7F).
                return Ok(unsafe { core::str::from_utf8_unchecked(b) });
            }
        } else {
            let bits = b[0] | b[n >> 1] | b[n - 1];
            if bits < 0x80 {
                // SAFETY: Every byte is ASCII (< 0x80).
                return Ok(unsafe { core::str::from_utf8_unchecked(b) });
            }
        }
        return validate_utf8_from(b, 0);
    }
    if n <= 32 {
        let w0 = u64::from_le_bytes(b[..8].try_into().unwrap());
        let w1 = u64::from_le_bytes(b[8..16].try_into().unwrap());
        let w2 = u64::from_le_bytes(b[n - 16..n - 8].try_into().unwrap());
        let w3 = u64::from_le_bytes(b[n - 8..n].try_into().unwrap());
        if ((w0 | w1 | w2 | w3) & 0x8080_8080_8080_8080) == 0 {
            // SAFETY: Every byte in 0..n has its high bit clear (0x00..=0x7F).
            return Ok(unsafe { core::str::from_utf8_unchecked(b) });
        }
        return validate_utf8_from(b, 0);
    }

    let mut i = 0usize;
    while i + 32 <= n {
        let w0 = u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        let w1 = u64::from_le_bytes(b[i + 8..i + 16].try_into().unwrap());
        let w2 = u64::from_le_bytes(b[i + 16..i + 24].try_into().unwrap());
        let w3 = u64::from_le_bytes(b[i + 24..i + 32].try_into().unwrap());
        if ((w0 | w1 | w2 | w3) & 0x8080_8080_8080_8080) != 0 {
            return validate_utf8_from(b, i);
        }
        i += 32;
    }
    if i < n {
        let t0 = u64::from_le_bytes(b[n - 32..n - 24].try_into().unwrap());
        let t1 = u64::from_le_bytes(b[n - 24..n - 16].try_into().unwrap());
        let t2 = u64::from_le_bytes(b[n - 16..n - 8].try_into().unwrap());
        let t3 = u64::from_le_bytes(b[n - 8..n].try_into().unwrap());
        if ((t0 | t1 | t2 | t3) & 0x8080_8080_8080_8080) != 0 {
            return validate_utf8_from(b, i);
        }
    }
    // SAFETY: Every byte in 0..n has its high bit clear (0x00..=0x7F).
    Ok(unsafe { core::str::from_utf8_unchecked(b) })
}

#[cold]
#[inline(never)]
fn validate_utf8_from(b: &[u8], ascii_prefix_len: usize) -> Result<&str> {
    core::str::from_utf8(&b[ascii_prefix_len..]).map_err(|_| Error::InvalidUtf8)?;
    // SAFETY: `b[..ascii_prefix_len]` is verified pure ASCII (< 0x80) and `b[ascii_prefix_len..]` is valid UTF-8.
    Ok(unsafe { core::str::from_utf8_unchecked(b) })
}

/// Reports whether `wt` is a valid 1-byte `KeyType` in a `WireMap` header.
#[inline]
pub const fn is_valid_map_key_wire_type(wt: u8) -> bool {
    matches!(
        wt,
        WIRE_UINT
            | WIRE_SINT
            | WIRE_BOOL_FALSE
            | WIRE_FIXED32
            | WIRE_FIXED64
            | WIRE_SFIXED32
            | WIRE_SFIXED64
            | WIRE_STRING
    )
}

/// Reports whether `wt` is a valid 1-byte `ValueType` in a `WireMap` header.
#[inline]
pub const fn is_valid_map_val_wire_type(wt: u8) -> bool {
    wt <= WIRE_EXTENDED && wt != WIRE_BOOL_TRUE
}

/// Parses and validates `[ElementType: 1B][Count: Prefix-Varint]` at the start of a `WireArray` body.
///
/// Returns `Some((elem_type, count, payload_offset))` if valid and bounded by `body.len()`.
#[inline]
pub fn parse_array_header(body: &[u8]) -> Option<(u8, usize, usize)> {
    if body.len() < 2 {
        return None;
    }
    let elem = body[0];
    if elem > WIRE_EXTENDED || elem == WIRE_BOOL_TRUE {
        return None;
    }
    let b1 = body[1];
    let (count_u64, n) = if (b1 & 1) != 0 {
        (u64::from(b1 >> 1), 1)
    } else {
        decode_varint(&body[1..])?
    };
    let pos = 1 + n;
    let remaining = body.len().checked_sub(pos)?;
    let count = usize::try_from(count_u64).ok()?;
    let width = match elem {
        WIRE_BOOL_FALSE => 1,
        WIRE_FIXED32 | WIRE_FLOAT32 | WIRE_SFIXED32 => 4,
        WIRE_FIXED64 | WIRE_FLOAT64 | WIRE_SFIXED64 => 8,
        _ => 0,
    };
    if width > 0 {
        if remaining % width != 0 || count != remaining / width {
            return None;
        }
    } else if (count == 0 && remaining != 0) || count > remaining {
        return None;
    }
    Some((elem, count, pos))
}

/// Parses and validates `[KeyType: 1B][ValueType: 1B][Count: Prefix-Varint]` at the start of a `WireMap` body.
#[inline]
pub fn parse_map_header(body: &[u8]) -> Option<(u8, u8, usize, usize)> {
    if body.len() < 3 {
        return None;
    }
    let key_wt = body[0];
    let val_wt = body[1];
    if !is_valid_map_key_wire_type(key_wt) || !is_valid_map_val_wire_type(val_wt) {
        return None;
    }
    let b2 = body[2];
    let (count_u64, n) = if (b2 & 1) != 0 {
        (u64::from(b2 >> 1), 1)
    } else {
        decode_varint(&body[2..])?
    };
    let pos = 2 + n;
    let remaining = body.len().checked_sub(pos)?;
    let count = usize::try_from(count_u64).ok()?;
    if (count == 0 && remaining != 0) || count > remaining / 2 {
        return None;
    }
    Some((key_wt, val_wt, count, pos))
}

#[cold]
#[inline(never)]
pub(crate) fn cold_parse_err(msg: &'static str) -> Error {
    Error::parse(msg)
}

/// Decodes a Prefix-Varint starting at `data[pos]`, returning `(value, next_pos)`.
#[inline(always)]
pub fn read_varint_at(data: &[u8], pos: usize) -> Result<(u64, usize)> {
    let n = data.len();
    if pos >= n {
        return Err(cold_parse_err("truncated varint"));
    }
    let b0 = data[pos];
    if (b0 & 1) != 0 {
        return Ok((u64::from(b0 >> 1), pos + 1));
    }
    if (b0 & 2) != 0 {
        if pos + 2 <= n {
            let raw: [u8; 2] = data[pos..pos + 2].try_into().unwrap();
            return Ok((u64::from(u16::from_le_bytes(raw) >> 2), pos + 2));
        }
        return Err(cold_parse_err("truncated 2-byte varint"));
    }
    if (b0 & 4) != 0 {
        if pos + 4 <= n {
            let raw: [u8; 4] = data[pos..pos + 4].try_into().unwrap();
            return Ok((u64::from(u32::from_le_bytes(raw) >> 3), pos + 4));
        }
        return Err(cold_parse_err("truncated 4-byte varint"));
    }
    if b0 == 0 {
        if pos + 9 <= n {
            let raw: [u8; 8] = data[pos + 1..pos + 9].try_into().unwrap();
            return Ok((u64::from_le_bytes(raw), pos + 9));
        }
        return Err(cold_parse_err("truncated 9-byte varint"));
    }
    Err(cold_parse_err("invalid varint marker"))
}

/// Reads a length-prefixed sub-slice starting at `data[pos]` with `byte_len >= min_len`.
#[inline(always)]
pub fn read_len_slice(data: &[u8], pos: usize, min_len: usize) -> Result<(&[u8], usize)> {
    let n = data.len();
    if pos >= n {
        return Err(cold_parse_err("position out of bounds"));
    }
    let b0 = data[pos];
    if (b0 & 1) != 0 {
        let len = usize::from(b0 >> 1);
        let start = pos + 1;
        if len >= min_len && len <= n - start {
            let end = start + len;
            return Ok((&data[start..end], end));
        }
        return Err(cold_parse_err("invalid container byteLen"));
    }
    if (b0 & 2) != 0 && pos + 2 <= n {
        let raw: [u8; 2] = data[pos..pos + 2].try_into().unwrap();
        let len = usize::from(u16::from_le_bytes(raw) >> 2);
        let start = pos + 2;
        if len >= min_len && len <= n - start {
            let end = start + len;
            return Ok((&data[start..end], end));
        }
        return Err(cold_parse_err("invalid container byteLen"));
    }
    read_len_slice_slow(data, pos, min_len)
}

#[cold]
#[inline(never)]
fn read_len_slice_slow(data: &[u8], pos: usize, min_len: usize) -> Result<(&[u8], usize)> {
    let rem = data
        .get(pos..)
        .ok_or_else(|| cold_parse_err("position out of bounds"))?;
    let (b_len, bn) =
        decode_varint(rem).ok_or_else(|| cold_parse_err("truncated or invalid length varint"))?;
    let start = pos + bn;
    let len = usize::try_from(b_len).map_err(|_| cold_parse_err("byteLen overflows usize"))?;
    if len < min_len || len > data.len() - start {
        return Err(cold_parse_err("invalid container byteLen"));
    }
    let end = start + len;
    Ok((&data[start..end], end))
}

/// Reads a `WireString` length-prefixed UTF-8 slice starting at `data[pos]`.
#[inline(always)]
pub fn read_str_slice(data: &[u8], pos: usize) -> Result<(&str, usize)> {
    let (bytes, next_pos) = read_len_slice(data, pos, 0)?;
    let s = validate_utf8(bytes)?;
    Ok((s, next_pos))
}

/// Advances `pos` past a single field payload in O(1) time without inspecting container bodies.
#[inline]
pub fn fast_skip_value(packet: &[u8], pos: usize, wt: u8) -> Option<usize> {
    let n = packet.len();
    match wt {
        WIRE_UINT | WIRE_SINT => {
            let vb = *packet.get(pos)?;
            let step = match vb.trailing_zeros() {
                0 => 1,
                1 => 2,
                2 => 4,
                8 => 9,
                _ => return None,
            };
            let end = pos + step;
            (end <= n).then_some(end)
        }
        WIRE_BOOL_FALSE | WIRE_BOOL_TRUE => (pos <= n).then_some(pos),
        WIRE_STRING | WIRE_BYTES | WIRE_SUB_MSG | WIRE_ARRAY | WIRE_MAP | WIRE_EXTENDED => {
            let lb = *packet.get(pos)?;
            if (lb & 1) != 0 {
                let len = usize::from(lb >> 1);
                let end = pos + 1 + len;
                return (end <= n).then_some(end);
            }
            if (lb & 2) != 0 {
                let raw: [u8; 2] = packet.get(pos..pos + 2)?.try_into().ok()?;
                let len = usize::from(u16::from_le_bytes(raw) >> 2);
                let end = pos + 2 + len;
                return (end <= n).then_some(end);
            }
            skip_large_container(packet, pos)
        }
        WIRE_FIXED32 | WIRE_FLOAT32 | WIRE_SFIXED32 => {
            let end = pos.checked_add(4)?;
            (end <= n).then_some(end)
        }
        WIRE_FIXED64 | WIRE_FLOAT64 | WIRE_SFIXED64 => {
            let end = pos.checked_add(8)?;
            (end <= n).then_some(end)
        }
        _ => None,
    }
}

#[cold]
#[inline(never)]
fn skip_large_container(packet: &[u8], pos: usize) -> Option<usize> {
    let (b_len, bn) = decode_varint(packet.get(pos..)?)?;
    let len = usize::try_from(b_len).ok()?;
    let start = pos.checked_add(bn)?;
    let end = start.checked_add(len)?;
    (end <= packet.len()).then_some(end)
}

/// Zero-allocation O(1) field skipper that also validates `WireArray` / `WireMap` / `WireExtended` headers.
#[inline]
pub fn skip_value_opt(b: &[u8], pos: usize, wire_type: u8) -> Option<usize> {
    if matches!(wire_type, WIRE_ARRAY | WIRE_MAP | WIRE_EXTENDED) {
        let (body, end) = read_len_slice(b, pos, 1).ok()?;
        match wire_type {
            WIRE_ARRAY => {
                parse_array_header(body)?;
            }
            WIRE_MAP => {
                parse_map_header(body)?;
            }
            _ => {}
        }
        return Some(end);
    }
    fast_skip_value(b, pos, wire_type)
}

/// Advances `pos` past a single field value, validating top-level container headers in O(1) time.
pub fn skip_value(b: &[u8], pos: usize, wire_type: u8) -> Result<usize> {
    if pos > b.len() {
        return Err(cold_parse_err("position out of bounds"));
    }
    skip_value_opt(b, pos, wire_type).ok_or_else(|| cold_parse_err("truncated or invalid wireType"))
}

/// Validates a field value recursively up to `MAX_NESTING_DEPTH`, including unknown containers and UTF-8 strings.
pub fn validate_value(data: &[u8], pos: usize, wire_type: u8, depth: usize) -> Result<usize> {
    validate_value_with_max_depth(data, pos, wire_type, depth, MAX_NESTING_DEPTH)
}

pub(crate) fn validate_value_with_max_depth(
    data: &[u8],
    pos: usize,
    wire_type: u8,
    depth: usize,
    max_depth: usize,
) -> Result<usize> {
    if depth > max_depth {
        return Err(Error::DepthLimitExceeded(depth));
    }
    if pos > data.len() {
        return Err(Error::parse(format!("position {pos} out of bounds")));
    }
    match wire_type {
        WIRE_STRING => {
            let (_, end) = read_str_slice(data, pos)?;
            Ok(end)
        }
        WIRE_SUB_MSG => {
            let (body, end) = read_len_slice(data, pos, 0)?;
            validate_message_with_max_depth(body, depth + 1, max_depth)?;
            Ok(end)
        }
        WIRE_ARRAY => {
            if depth + 1 > max_depth {
                return Err(Error::DepthLimitExceeded(depth + 1));
            }
            let (body, end) = read_len_slice(data, pos, 2)?;
            let (elem_wt, count, start_p) =
                parse_array_header(body).ok_or_else(|| Error::parse("invalid array header"))?;
            validate_array_body(body, start_p, elem_wt, count, depth + 1, max_depth)?;
            Ok(end)
        }
        WIRE_MAP => {
            if depth + 1 > max_depth {
                return Err(Error::DepthLimitExceeded(depth + 1));
            }
            let (body, end) = read_len_slice(data, pos, 3)?;
            let (key_wt, val_wt, count, mut p) =
                parse_map_header(body).ok_or_else(|| Error::parse("invalid map header"))?;
            for _ in 0..count {
                p = validate_container_entry(body, p, key_wt, depth + 1, max_depth)?;
                p = validate_container_entry(body, p, val_wt, depth + 1, max_depth)?;
            }
            if p != body.len() {
                return Err(Error::parse("trailing map bytes"));
            }
            Ok(end)
        }
        WIRE_EXTENDED => {
            let (_, end) = read_len_slice(data, pos, 1)?;
            Ok(end)
        }
        _ => fast_skip_value(data, pos, wire_type).ok_or_else(|| {
            Error::parse(format!(
                "truncated or invalid wireType {wire_type} at {pos}"
            ))
        }),
    }
}

fn validate_array_body(
    body: &[u8],
    mut p: usize,
    elem_wt: u8,
    count: usize,
    depth: usize,
    max_depth: usize,
) -> Result<()> {
    match elem_wt {
        WIRE_BOOL_FALSE => {
            if body.len() - p != count {
                return Err(Error::parse("invalid bool array length"));
            }
            for &b in &body[p..p + count] {
                if b > 1 {
                    return Err(Error::parse("invalid bool byte in array"));
                }
            }
            return Ok(());
        }
        WIRE_FIXED32 | WIRE_SFIXED32 | WIRE_FLOAT32 => {
            if body.len() - p != count * 4 {
                return Err(Error::parse("invalid 32-bit array length"));
            }
            return Ok(());
        }
        WIRE_FIXED64 | WIRE_SFIXED64 | WIRE_FLOAT64 => {
            if body.len() - p != count * 8 {
                return Err(Error::parse("invalid 64-bit array length"));
            }
            return Ok(());
        }
        _ => {}
    }
    for _ in 0..count {
        p = validate_container_entry(body, p, elem_wt, depth, max_depth)?;
    }
    if p != body.len() {
        return Err(Error::parse("trailing array bytes"));
    }
    Ok(())
}

fn validate_container_entry(
    body: &[u8],
    p: usize,
    wt: u8,
    depth: usize,
    max_depth: usize,
) -> Result<usize> {
    if wt == WIRE_BOOL_FALSE {
        let b = *body
            .get(p)
            .ok_or_else(|| Error::parse("truncated bool in container"))?;
        if b > 1 {
            return Err(Error::parse("invalid bool byte in container"));
        }
        return Ok(p + 1);
    }
    validate_value_with_max_depth(body, p, wt, depth, max_depth)
}

/// Validates an entire OmniBuf message buffer recursively up to `MAX_NESTING_DEPTH`.
pub fn validate_message(data: &[u8], depth: usize) -> Result<()> {
    validate_message_with_max_depth(data, depth, MAX_NESTING_DEPTH)
}

pub(crate) fn validate_message_with_max_depth(
    data: &[u8],
    depth: usize,
    max_depth: usize,
) -> Result<()> {
    if depth > max_depth {
        return Err(Error::DepthLimitExceeded(depth));
    }
    let mut pos = 0;
    let n = data.len();
    while pos < n {
        let (tag, tn) = decode_varint(&data[pos..])
            .ok_or_else(|| Error::parse(format!("invalid or truncated tag at {pos}")))?;
        if (tag >> 4) > MAX_FIELD_NUMBER {
            return Err(Error::parse("field number exceeds maximum 29-bit limit"));
        }
        pos += tn;
        let fnum = tag >> 4;
        let wt = (tag & 0x0F) as u8;
        if fnum == 0 {
            if wt != WIRE_SUB_MSG {
                return Err(Error::parse(format!("invalid Field #0 wire type {wt}")));
            }
            pos = validate_field0_with_max_depth(data, pos, depth, max_depth)?;
        } else {
            pos = validate_value_with_max_depth(data, pos, wt, depth, max_depth)?;
        }
    }
    Ok(())
}

/// Decodes a field tag at `packet[pos..]`, returning `(field_num, wire_type, next_pos)`.
#[inline]
pub fn read_tag_at(packet: &[u8], pos: usize) -> Option<(u32, u8, usize)> {
    let b0 = *packet.get(pos)?;
    if (b0 & 1) != 0 {
        return Some((u32::from(b0 >> 5), (b0 >> 1) & 0x0F, pos + 1));
    }
    if (b0 & 2) != 0 {
        let raw: [u8; 2] = packet.get(pos..pos + 2)?.try_into().ok()?;
        let u = u16::from_le_bytes(raw) >> 2;
        return Some((u32::from(u >> 4), (u & 0x0F) as u8, pos + 2));
    }
    let (tag, tn) = decode_varint(&packet[pos..])?;
    if (tag >> 4) > MAX_FIELD_NUMBER {
        return None;
    }
    Some(((tag >> 4) as u32, (tag & 0x0F) as u8, pos + tn))
}

/// Locates `target_field` in `packet` by hopping field headers in O(1) time per field.
///
/// Scans to the end of `packet` so concatenated messages obey "last write wins" semantics.
#[inline]
pub fn locate_field(packet: &[u8], target_field: u16) -> Option<(&[u8], u8)> {
    locate_field_mask(packet, target_field, 0xFFFF)
}

/// Locates `target_field` matching `exp_mask` (`1 << wire_type`) in `packet`.
#[inline]
pub fn locate_field_mask(packet: &[u8], target_field: u16, exp_mask: u16) -> Option<(&[u8], u8)> {
    let mut pos = 0;
    let n = packet.len();
    let mut found: Option<(&[u8], u8)> = None;

    while pos < n {
        let (fnum, wt, next_pos) = read_tag_at(packet, pos)?;
        pos = next_pos;
        if fnum == 0 {
            if wt != WIRE_SUB_MSG {
                return None;
            }
            let end = validate_field0(packet, pos, 0).ok()?;
            if target_field == 0 && (exp_mask & (1u16 << wt)) != 0 {
                found = Some((&packet[pos..], wt));
            }
            pos = end;
            continue;
        }
        if fnum == u32::from(target_field) && (exp_mask & (1u16 << wt)) != 0 {
            found = Some((&packet[pos..], wt));
        }
        pos = skip_value_opt(packet, pos, wt)?;
    }
    found
}

/// Iterates matching container occurrences for `target_field` across `packet`.
///
/// Returns `(Some((body, next_pos)), true)` on a match, `(None, true)` at clean end-of-packet,
/// or `(None, false)` if `packet` is malformed.
#[inline]
pub fn next_container_field(
    packet: &[u8],
    mut pos: usize,
    target_field: u16,
    exp_wt: u8,
    min_len: usize,
    strict_target_wt: bool,
) -> (Option<(&[u8], usize)>, bool) {
    let n = packet.len();
    while pos < n {
        let Some((fnum, wt, after_tag)) = read_tag_at(packet, pos) else {
            return (None, false);
        };
        pos = after_tag;
        if fnum == 0 {
            if wt != WIRE_SUB_MSG {
                return (None, false);
            }
            let Ok(end) = validate_field0(packet, pos, 0) else {
                return (None, false);
            };
            if target_field == 0 {
                if exp_wt == WIRE_SUB_MSG {
                    let Ok((body, _)) = read_len_slice(packet, pos, min_len) else {
                        return (None, false);
                    };
                    return (Some((body, end)), true);
                } else if strict_target_wt {
                    return (None, false);
                }
            }
            pos = end;
            continue;
        }
        if fnum == u32::from(target_field) {
            if wt == exp_wt {
                let Ok((body, end)) = read_len_slice(packet, pos, min_len) else {
                    return (None, false);
                };
                return (Some((body, end)), true);
            } else if strict_target_wt {
                return (None, false);
            }
        }
        let Some(next_pos) = skip_value_opt(packet, pos, wt) else {
            return (None, false);
        };
        pos = next_pos;
    }
    (None, true)
}

// ============================================================================
// O(1) Zero-Copy Field Readers (Used by Opaque<T> Views and Direct Queries)
// ============================================================================

/// Reads an unsigned integer field (`WireUint`) without heap allocation.
#[inline]
pub fn read_uint(packet: &[u8], field_num: u16) -> Option<u64> {
    let (s, _) = locate_field_mask(packet, field_num, 1 << WIRE_UINT)?;
    decode_varint(s).map(|(v, _)| v)
}

/// Reads a ZigZag-encoded signed integer field (`WireSint`) without heap allocation.
#[inline]
pub fn read_sint(packet: &[u8], field_num: u16) -> Option<i64> {
    let (s, _) = locate_field_mask(packet, field_num, 1 << WIRE_SINT)?;
    decode_varint(s).map(|(v, _)| decode_zigzag(v))
}

/// Reads a boolean field (`WireBoolFalse` / `WireBoolTrue`) directly from the 4-bit wire type.
#[inline]
pub fn read_bool(packet: &[u8], field_num: u16) -> Option<bool> {
    let (_, wt) = locate_field_mask(
        packet,
        field_num,
        (1 << WIRE_BOOL_FALSE) | (1 << WIRE_BOOL_TRUE),
    )?;
    Some(wt == WIRE_BOOL_TRUE)
}

/// Reads a 4-byte little-endian `u32` field (`WireFixed32`).
#[inline]
pub fn read_fixed32(packet: &[u8], field_num: u16) -> Option<u32> {
    let (s, _) = locate_field_mask(packet, field_num, 1 << WIRE_FIXED32)?;
    let raw: [u8; 4] = s.get(..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
}

/// Reads an 8-byte little-endian `u64` field (`WireFixed64`).
#[inline]
pub fn read_fixed64(packet: &[u8], field_num: u16) -> Option<u64> {
    let (s, _) = locate_field_mask(packet, field_num, 1 << WIRE_FIXED64)?;
    let raw: [u8; 8] = s.get(..8)?.try_into().ok()?;
    Some(u64::from_le_bytes(raw))
}

/// Reads a 4-byte little-endian `i32` field (`WireSfixed32`).
#[inline]
pub fn read_sfixed32(packet: &[u8], field_num: u16) -> Option<i32> {
    let (s, _) = locate_field_mask(packet, field_num, 1 << WIRE_SFIXED32)?;
    let raw: [u8; 4] = s.get(..4)?.try_into().ok()?;
    Some(i32::from_le_bytes(raw))
}

/// Reads an 8-byte little-endian `i64` field (`WireSfixed64`).
#[inline]
pub fn read_sfixed64(packet: &[u8], field_num: u16) -> Option<i64> {
    let (s, _) = locate_field_mask(packet, field_num, 1 << WIRE_SFIXED64)?;
    let raw: [u8; 8] = s.get(..8)?.try_into().ok()?;
    Some(i64::from_le_bytes(raw))
}

/// Reads a 4-byte IEEE-754 `f32` field (`WireFloat32`).
#[inline]
pub fn read_float32(packet: &[u8], field_num: u16) -> Option<f32> {
    let (s, _) = locate_field_mask(packet, field_num, 1 << WIRE_FLOAT32)?;
    let raw: [u8; 4] = s.get(..4)?.try_into().ok()?;
    Some(f32::from_bits(u32::from_le_bytes(raw)))
}

/// Reads an 8-byte IEEE-754 `f64` field (`WireFloat64`).
#[inline]
pub fn read_float64(packet: &[u8], field_num: u16) -> Option<f64> {
    let (s, _) = locate_field_mask(packet, field_num, 1 << WIRE_FLOAT64)?;
    let raw: [u8; 8] = s.get(..8)?.try_into().ok()?;
    Some(f64::from_bits(u64::from_le_bytes(raw)))
}

/// Zero-copy UTF-8 string reader borrowing directly from `packet`.
#[inline]
pub fn read_str(packet: &[u8], field_num: u16) -> Option<&str> {
    let (s, _) = locate_field_mask(packet, field_num, 1 << WIRE_STRING)?;
    let (str_ref, _) = read_str_slice(s, 0).ok()?;
    Some(str_ref)
}

/// Zero-copy byte slice reader borrowing directly from `packet`.
#[inline]
pub fn read_bytes(packet: &[u8], field_num: u16) -> Option<&[u8]> {
    let (s, _) = locate_field_mask(packet, field_num, 1 << WIRE_BYTES)?;
    let (bytes, _) = read_len_slice(s, 0, 0).ok()?;
    Some(bytes)
}

/// Reads a nested `WireSubMsg` field, borrowing zero-copy when present once or concatenating merged segments.
#[inline]
pub fn read_sub_msg(packet: &[u8], field_num: u16) -> Option<Cow<'_, [u8]>> {
    let (matched, valid) = next_container_field(packet, 0, field_num, WIRE_SUB_MSG, 0, false);
    if !valid {
        return None;
    }
    let (first, pos) = matched?;
    let (second, valid2) = next_container_field(packet, pos, field_num, WIRE_SUB_MSG, 0, false);
    if !valid2 {
        return None;
    }
    match second {
        None => Some(Cow::Borrowed(first)),
        Some((body2, pos2)) => read_sub_msg_merged(packet, field_num, first, body2, pos2),
    }
}

#[cold]
#[inline(never)]
fn read_sub_msg_merged<'a>(
    packet: &'a [u8],
    field_num: u16,
    first: &'a [u8],
    second: &'a [u8],
    mut pos: usize,
) -> Option<Cow<'a, [u8]>> {
    let mut merged = Vec::with_capacity(first.len() + second.len());
    merged.extend_from_slice(first);
    merged.extend_from_slice(second);
    loop {
        let (matched, valid) = next_container_field(packet, pos, field_num, WIRE_SUB_MSG, 0, false);
        if !valid {
            return None;
        }
        let Some((body, next_pos)) = matched else {
            return Some(Cow::Owned(merged));
        };
        pos = next_pos;
        merged.extend_from_slice(body);
    }
}

/// Returns the combined element count for `WireArray` fields of `elem_type`.
pub fn counted_arr_len(packet: &[u8], field_num: u16, elem_type: u8) -> usize {
    let mut total = 0usize;
    let mut pos = 0usize;
    loop {
        let (matched, valid) = next_container_field(packet, pos, field_num, WIRE_ARRAY, 2, false);
        if !valid {
            return 0;
        }
        let Some((body, next_pos)) = matched else {
            return total;
        };
        pos = next_pos;
        let Some((e, count, mut p)) = parse_array_header(body) else {
            return 0;
        };
        if e != elem_type {
            return 0;
        }
        // Verify variable-width elements actually match `count` and consume `body`.
        match elem_type {
            WIRE_BOOL_FALSE => {
                if body[p..].iter().any(|&b| b > 1) {
                    return 0;
                }
            }
            WIRE_FIXED32 | WIRE_SFIXED32 | WIRE_FLOAT32 | WIRE_FIXED64 | WIRE_SFIXED64
            | WIRE_FLOAT64 => {}
            WIRE_UINT | WIRE_SINT => {
                for _ in 0..count {
                    let Some((_, vn)) = decode_varint(&body[p..]) else {
                        return 0;
                    };
                    p += vn;
                }
                if p != body.len() {
                    return 0;
                }
            }
            WIRE_STRING => {
                for _ in 0..count {
                    let Ok((_, next_p)) = read_str_slice(body, p) else {
                        return 0;
                    };
                    p = next_p;
                }
                if p != body.len() {
                    return 0;
                }
            }
            WIRE_BYTES | WIRE_SUB_MSG => {
                for _ in 0..count {
                    let Ok((_, next_p)) = read_len_slice(body, p, 0) else {
                        return 0;
                    };
                    p = next_p;
                }
                if p != body.len() {
                    return 0;
                }
            }
            _ => return 0,
        }
        total += count;
    }
}

/// Counts and validates elements in a `WireArray(WireSubMsg)` body.
pub fn count_sub_msg_arr_elems(body: &[u8]) -> Option<usize> {
    let (elem, count, mut p) = parse_array_header(body)?;
    if elem != WIRE_SUB_MSG {
        return None;
    }
    for _ in 0..count {
        let (_, next_p) = read_len_slice(body, p, 0).ok()?;
        p = next_p;
    }
    (p == body.len()).then_some(count)
}

/// Returns the total element count of a `WireArray(WireSubMsg)` field across concatenated segments.
pub fn sub_msg_arr_len(packet: &[u8], field_num: u16) -> usize {
    let mut total = 0usize;
    let mut pos = 0usize;
    loop {
        let (matched, valid) = next_container_field(packet, pos, field_num, WIRE_ARRAY, 2, false);
        if !valid {
            return 0;
        }
        let Some((body, next_pos)) = matched else {
            return total;
        };
        pos = next_pos;
        let Some(c) = count_sub_msg_arr_elems(body) else {
            return 0;
        };
        total += c;
    }
}

/// Slices the `index`-th sub-message element out of a `WireArray(WireSubMsg)` body.
pub fn read_elem(body: &[u8], index: usize) -> Option<&[u8]> {
    let (elem, count, mut p) = parse_array_header(body)?;
    if elem != WIRE_SUB_MSG || index >= count {
        return None;
    }
    let mut target: Option<&[u8]> = None;
    for i in 0..count {
        let (slice, next_p) = read_len_slice(body, p, 0).ok()?;
        if i == index {
            target = Some(slice);
        }
        p = next_p;
    }
    (p == body.len()).then_some(target).flatten()
}

/// Slices the `index`-th sub-message element from `field_num` across concatenated `WireArray` segments.
pub fn read_sub_msg_arr_elem(packet: &[u8], field_num: u16, index: usize) -> Option<&[u8]> {
    let mut rem_idx = index;
    let mut found: Option<&[u8]> = None;
    let mut pos = 0usize;
    loop {
        let (matched, valid) = next_container_field(packet, pos, field_num, WIRE_ARRAY, 2, false);
        if !valid {
            return None;
        }
        let Some((body, next_pos)) = matched else {
            return found;
        };
        pos = next_pos;
        if found.is_none()
            && let Some(elem) = read_elem(body, rem_idx)
        {
            found = Some(elem);
            continue;
        }
        let c = count_sub_msg_arr_elems(body)?;
        rem_idx = rem_idx.saturating_sub(c);
    }
}

/// Reads a zero-copy nested string field (`sub_msg_field.target_field`) without unpacking intermediate fields.
pub fn read_nested_str(packet: &[u8], sub_msg_field: u16, target_field: u16) -> Option<&str> {
    let mut last: Option<&str> = None;
    let mut pos = 0usize;
    loop {
        let (matched, valid) =
            next_container_field(packet, pos, sub_msg_field, WIRE_SUB_MSG, 0, false);
        if !valid {
            return None;
        }
        let Some((sub, next_pos)) = matched else {
            return last;
        };
        pos = next_pos;
        if let Some(s) = read_str(sub, target_field) {
            last = Some(s);
        }
    }
}

/// Reads a zero-copy string inside the `index`-th repeated sub-message (`arr_field[index].target_field`).
pub fn read_arr_nested_str(
    packet: &[u8],
    arr_field: u16,
    index: usize,
    target_field: u16,
) -> Option<&str> {
    let elem = read_sub_msg_arr_elem(packet, arr_field, index)?;
    read_str(elem, target_field)
}

/// Reads a zero-copy `Vec<&str>` from a `WireArray(WireString)` field across concatenated segments.
pub fn read_string_arr(packet: &[u8], field_num: u16) -> Option<Vec<&str>> {
    let mut out = Vec::new();
    let mut found = false;
    let mut pos = 0usize;
    loop {
        let (matched, valid) = next_container_field(packet, pos, field_num, WIRE_ARRAY, 2, false);
        if !valid {
            return None;
        }
        let Some((body, next_pos)) = matched else {
            return found.then_some(out);
        };
        pos = next_pos;
        let (elem, count, mut p) = parse_array_header(body)?;
        if elem != WIRE_STRING {
            return None;
        }
        let cap_add = count.min(4096);
        let total = out.len().saturating_add(cap_add);
        if out.capacity() < total {
            out.reserve(grow_capacity(out.capacity(), total) - out.len());
        }
        for _ in 0..count {
            let (s, next_p) = read_str_slice(body, p).ok()?;
            out.push(s);
            p = next_p;
        }
        if p != body.len() {
            return None;
        }
        found = true;
    }
}

/// Reads a `Vec<u32>` from a `WireArray(WireUint)` field across concatenated segments.
pub fn read_uint32_arr(packet: &[u8], field_num: u16) -> Option<Vec<u32>> {
    let mut out = Vec::new();
    let mut found = false;
    let mut pos = 0usize;
    loop {
        let (matched, valid) = next_container_field(packet, pos, field_num, WIRE_ARRAY, 2, false);
        if !valid {
            return None;
        }
        let Some((body, next_pos)) = matched else {
            return found.then_some(out);
        };
        pos = next_pos;
        let (elem, count, mut p) = parse_array_header(body)?;
        if elem != WIRE_UINT {
            return None;
        }
        let cap_add = count.min(4096);
        let total = out.len().saturating_add(cap_add);
        if out.capacity() < total {
            out.reserve(grow_capacity(out.capacity(), total) - out.len());
        }
        for _ in 0..count {
            let (v, vn) = decode_varint(&body[p..])?;
            out.push(v as u32);
            p += vn;
        }
        if p != body.len() {
            return None;
        }
        found = true;
    }
}

/// Searches a `WireMap<WireString, WireUint>` field for `target_key` with zero map allocations.
pub fn lookup_map_string_uint(packet: &[u8], field_num: u16, target_key: &str) -> Option<u64> {
    let mut last_val: Option<u64> = None;
    let mut pos = 0usize;
    loop {
        let (matched, valid) = next_container_field(packet, pos, field_num, WIRE_MAP, 3, false);
        if !valid {
            return None;
        }
        let Some((body, next_pos)) = matched else {
            return last_val;
        };
        pos = next_pos;
        let (key_wt, val_wt, count, mut p) = parse_map_header(body)?;
        if key_wt != WIRE_STRING || val_wt != WIRE_UINT {
            return None;
        }
        for _ in 0..count {
            let (k, after_k) = read_str_slice(body, p).ok()?;
            let (v, vn) = decode_varint(&body[after_k..])?;
            p = after_k + vn;
            if k == target_key {
                last_val = Some(v);
            }
        }
        if p != body.len() {
            return None;
        }
    }
}

/// Searches a `WireMap<WireString, WireString>` field for `target_key` with zero map allocations.
pub fn lookup_map_string_str<'a>(
    packet: &'a [u8],
    field_num: u16,
    target_key: &str,
) -> Option<&'a str> {
    let mut last_val: Option<&'a str> = None;
    let mut pos = 0usize;
    loop {
        let (matched, valid) = next_container_field(packet, pos, field_num, WIRE_MAP, 3, false);
        if !valid {
            return None;
        }
        let Some((body, next_pos)) = matched else {
            return last_val;
        };
        pos = next_pos;
        let (key_wt, val_wt, count, mut p) = parse_map_header(body)?;
        if key_wt != WIRE_STRING || val_wt != WIRE_STRING {
            return None;
        }
        for _ in 0..count {
            let (k, after_k) = read_str_slice(body, p).ok()?;
            let (v, after_v) = read_str_slice(body, after_k).ok()?;
            p = after_v;
            if k == target_key {
                last_val = Some(v);
            }
        }
        if p != body.len() {
            return None;
        }
    }
}

/// Reads a `WireMap<WireString, WireUint>` field into a `HashMap<String, u64>`.
pub fn read_map_string_uint(packet: &[u8], field_num: u16) -> Option<HashMap<String, u64>> {
    let mut out: Option<HashMap<String, u64>> = None;
    let mut pos = 0usize;
    loop {
        let (matched, valid) = next_container_field(packet, pos, field_num, WIRE_MAP, 3, false);
        if !valid {
            return None;
        }
        let Some((body, next_pos)) = matched else {
            return out;
        };
        pos = next_pos;
        let (key_wt, val_wt, count, mut p) = parse_map_header(body)?;
        if key_wt != WIRE_STRING || val_wt != WIRE_UINT {
            return None;
        }
        let map = out.get_or_insert_with(|| HashMap::with_capacity(count.min(4096)));
        for _ in 0..count {
            let (k, after_k) = read_str_slice(body, p).ok()?;
            let (v, vn) = decode_varint(&body[after_k..])?;
            p = after_k + vn;
            map.insert(k.to_owned(), v);
        }
        if p != body.len() {
            return None;
        }
    }
}

/// Encodes a `HashMap<String, u64>` as a `WireMap<WireString, WireUint>` container body (including length prefix).
pub fn encode_map_string_uint(dst: &mut Vec<u8>, m: &HashMap<String, u64>, deterministic: bool) {
    let len_pos = dst.len();
    dst.extend_from_slice(&[0, 0, WIRE_STRING, WIRE_UINT]);
    append_varint(dst, m.len() as u64);
    if deterministic && m.len() > 1 {
        let mut keys: Vec<&str> = m.keys().map(String::as_str).collect();
        if keys.len() <= 16 {
            for i in 1..keys.len() {
                let mut j = i;
                while j > 0 && keys[j] < keys[j - 1] {
                    keys.swap(j, j - 1);
                    j -= 1;
                }
            }
        } else {
            keys.sort_unstable();
        }
        for k in keys {
            append_varint(dst, k.len() as u64);
            dst.extend_from_slice(k.as_bytes());
            append_varint(dst, m[k]);
        }
    } else {
        for (k, &v) in m {
            append_varint(dst, k.len() as u64);
            dst.extend_from_slice(k.as_bytes());
            append_varint(dst, v);
        }
    }
    backpatch_container_len(dst, len_pos);
}

/// Encodes a `BTreeMap<String, u64>` as a `WireMap<WireString, WireUint>` container body (sorted naturally).
pub fn encode_btree_map_string_uint(dst: &mut Vec<u8>, m: &BTreeMap<String, u64>) {
    let len_pos = dst.len();
    dst.extend_from_slice(&[0, 0, WIRE_STRING, WIRE_UINT]);
    append_varint(dst, m.len() as u64);
    for (k, &v) in m {
        append_varint(dst, k.len() as u64);
        dst.extend_from_slice(k.as_bytes());
        append_varint(dst, v);
    }
    backpatch_container_len(dst, len_pos);
}

// ============================================================================
// Single-Pass Streaming Encoder
// ============================================================================

/// Encodes OmniBuf messages into a contiguous buffer in a single forward pass.
///
/// Uses an inline 64-slot stack for container backpatching and dynamically overflows
/// to heap storage if container nesting exceeds 64 open slots.
#[derive(Debug, Clone)]
pub struct Encoder {
    buf: Vec<u8>,
    len_stack: [usize; INLINE_STACK_SLOTS],
    count_stack: [usize; INLINE_STACK_SLOTS],
    depth: usize,
    len_overflow: Vec<usize>,
    count_overflow: Vec<usize>,
}

const FRAME_CONTAINER: usize = usize::MAX;

impl Default for Encoder {
    fn default() -> Self {
        Self::new(256)
    }
}

impl Encoder {
    /// Creates an `Encoder` with the given initial byte capacity.
    #[inline]
    pub fn new(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
            len_stack: [0; INLINE_STACK_SLOTS],
            count_stack: [0; INLINE_STACK_SLOTS],
            depth: 0,
            len_overflow: Vec::new(),
            count_overflow: Vec::new(),
        }
    }

    /// Creates an `Encoder` wrapping an existing `Vec<u8>` buffer (preserving any existing prefix).
    #[inline]
    pub fn from_vec(buf: Vec<u8>) -> Self {
        Self {
            buf,
            len_stack: [0; INLINE_STACK_SLOTS],
            count_stack: [0; INLINE_STACK_SLOTS],
            depth: 0,
            len_overflow: Vec::new(),
            count_overflow: Vec::new(),
        }
    }

    /// Clears the encoded bytes while retaining buffer capacity for reuse.
    #[inline]
    pub fn reset(&mut self) {
        self.buf.clear();
        self.depth = 0;
    }

    /// Borrows the encoded packet bytes written so far.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Consumes the encoder and returns the underlying `Vec<u8>`.
    #[inline]
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    /// Mutable access to the underlying byte buffer.
    #[inline]
    pub fn buf_mut(&mut self) -> &mut Vec<u8> {
        &mut self.buf
    }

    /// Appends pre-encoded raw bytes (such as a precomputed `Field #0` block).
    #[inline]
    pub fn write_raw(&mut self, raw: &[u8]) {
        self.buf.extend_from_slice(raw);
    }

    /// Appends a field tag `(field_num << 4) | wire_type`.
    #[inline]
    pub fn write_tag(&mut self, field_num: u32, wire_type: u8) {
        let tag = (u64::from(field_num) << 4) | u64::from(wire_type & 0x0F);
        append_varint(&mut self.buf, tag);
    }

    #[cold]
    #[inline(never)]
    fn push_overflow(&mut self, len_pos: usize, count: usize) {
        let idx = self.depth - INLINE_STACK_SLOTS;
        if idx < self.len_overflow.len() {
            self.len_overflow[idx] = len_pos;
            self.count_overflow[idx] = count;
        } else {
            self.len_overflow.push(len_pos);
            self.count_overflow.push(count);
        }
    }

    #[inline]
    fn push_frame(&mut self, len_pos: usize, count: usize) {
        if self.depth < INLINE_STACK_SLOTS {
            self.len_stack[self.depth] = len_pos;
            self.count_stack[self.depth] = count;
        } else {
            self.push_overflow(len_pos, count);
        }
        self.depth += 1;
    }

    #[inline]
    fn pop_frame(&mut self) -> (usize, usize) {
        self.depth -= 1;
        if self.depth < INLINE_STACK_SLOTS {
            (self.len_stack[self.depth], self.count_stack[self.depth])
        } else {
            let idx = self.depth - INLINE_STACK_SLOTS;
            (self.len_overflow[idx], self.count_overflow[idx])
        }
    }

    /// Begins an untagged length-prefixed container by reserving a 2-byte `Prefix-Varint` slot.
    #[inline]
    pub fn begin_container(&mut self) {
        let pos = self.buf.len();
        self.push_frame(pos, FRAME_CONTAINER);
        self.buf.extend_from_slice(&[0, 0]);
    }

    /// Finishes the current open container and backpatches its byte length.
    #[inline]
    pub fn end_container(&mut self) {
        assert!(
            self.depth > 0,
            "end_container called with no open container"
        );
        let (len_pos, kind) = self.pop_frame();
        assert!(
            kind == FRAME_CONTAINER,
            "end_container cannot close a begin_sub_msg_arr frame"
        );
        backpatch_container_len(&mut self.buf, len_pos);
    }

    /// Begins a nested sub-message field (`WireSubMsg`).
    #[inline]
    pub fn begin_sub_msg(&mut self, field_num: u32) {
        self.write_tag(field_num, WIRE_SUB_MSG);
        self.begin_container();
    }

    /// Finishes the current nested sub-message field and backpatches its byte length.
    #[inline]
    pub fn end_sub_msg(&mut self) {
        self.end_container();
    }

    /// Begins a streaming repeated sub-message array (`WireArray(WireSubMsg)`).
    #[inline]
    pub fn begin_sub_msg_arr(&mut self, field_num: u32) {
        self.write_tag(field_num, WIRE_ARRAY);
        let pos = self.buf.len();
        self.push_frame(pos, 0);
        self.buf.extend_from_slice(&[0, 0, WIRE_SUB_MSG, 0]);
    }

    /// Begins the next sub-message element inside an open `begin_sub_msg_arr` container.
    #[inline]
    pub fn begin_sub_msg_elem(&mut self) {
        assert!(
            self.depth > 0,
            "begin_sub_msg_elem requires an open begin_sub_msg_arr frame"
        );
        let parent = self.depth - 1;
        if parent < INLINE_STACK_SLOTS {
            let cur = self.count_stack[parent];
            assert!(
                cur != FRAME_CONTAINER,
                "begin_sub_msg_elem requires an open begin_sub_msg_arr frame"
            );
            let next = cur.checked_add(1).expect("sub_msg_arr count overflow");
            assert!(next != FRAME_CONTAINER, "sub_msg_arr count overflow");
            self.count_stack[parent] = next;
        } else {
            let idx = parent - INLINE_STACK_SLOTS;
            let cur = self.count_overflow[idx];
            assert!(
                cur != FRAME_CONTAINER,
                "begin_sub_msg_elem requires an open begin_sub_msg_arr frame"
            );
            let next = cur.checked_add(1).expect("sub_msg_arr count overflow");
            assert!(next != FRAME_CONTAINER, "sub_msg_arr count overflow");
            self.count_overflow[idx] = next;
        }
        self.begin_container();
    }

    /// Finishes the current sub-message element inside an open `begin_sub_msg_arr` container.
    #[inline]
    pub fn end_sub_msg_elem(&mut self) {
        self.end_container();
    }

    /// Finishes the open `begin_sub_msg_arr` container, patching both element count and total byte length.
    #[inline]
    pub fn end_sub_msg_arr(&mut self) {
        assert!(
            self.depth > 0,
            "end_sub_msg_arr called with no open begin_sub_msg_arr frame"
        );
        let (len_pos, count) = self.pop_frame();
        assert!(
            count != FRAME_CONTAINER,
            "end_sub_msg_arr requires an open begin_sub_msg_arr frame"
        );
        patch_reserved_varint(&mut self.buf, len_pos + 3, count as u64);
        backpatch_container_len(&mut self.buf, len_pos);
    }

    /// Writes an unsigned integer field (`WireUint`).
    #[inline]
    pub fn write_uint(&mut self, field_num: u32, v: u64) {
        self.write_tag(field_num, WIRE_UINT);
        append_varint(&mut self.buf, v);
    }

    /// Writes a ZigZag-encoded signed integer field (`WireSint`).
    #[inline]
    pub fn write_sint(&mut self, field_num: u32, v: i64) {
        self.write_tag(field_num, WIRE_SINT);
        append_varint(&mut self.buf, encode_zigzag(v));
    }

    /// Writes a zero-payload boolean field (`WireBoolFalse` or `WireBoolTrue`).
    #[inline]
    pub fn write_bool(&mut self, field_num: u32, v: bool) {
        self.write_tag(field_num, if v { WIRE_BOOL_TRUE } else { WIRE_BOOL_FALSE });
    }

    /// Writes a 4-byte little-endian `u32` field (`WireFixed32`).
    #[inline]
    pub fn write_fixed32(&mut self, field_num: u32, v: u32) {
        self.write_tag(field_num, WIRE_FIXED32);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Writes an 8-byte little-endian `u64` field (`WireFixed64`).
    #[inline]
    pub fn write_fixed64(&mut self, field_num: u32, v: u64) {
        self.write_tag(field_num, WIRE_FIXED64);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Writes a 4-byte little-endian `i32` field (`WireSfixed32`).
    #[inline]
    pub fn write_sfixed32(&mut self, field_num: u32, v: i32) {
        self.write_tag(field_num, WIRE_SFIXED32);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Writes an 8-byte little-endian `i64` field (`WireSfixed64`).
    #[inline]
    pub fn write_sfixed64(&mut self, field_num: u32, v: i64) {
        self.write_tag(field_num, WIRE_SFIXED64);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Writes a 4-byte IEEE-754 `f32` field (`WireFloat32`).
    #[inline]
    pub fn write_float32(&mut self, field_num: u32, v: f32) {
        self.write_tag(field_num, WIRE_FLOAT32);
        self.buf.extend_from_slice(&v.to_bits().to_le_bytes());
    }

    /// Writes an 8-byte IEEE-754 `f64` field (`WireFloat64`).
    #[inline]
    pub fn write_float64(&mut self, field_num: u32, v: f64) {
        self.write_tag(field_num, WIRE_FLOAT64);
        self.buf.extend_from_slice(&v.to_bits().to_le_bytes());
    }

    /// Writes a UTF-8 string field (`WireString`).
    #[inline]
    pub fn write_string(&mut self, field_num: u32, s: &str) {
        self.write_tag(field_num, WIRE_STRING);
        append_varint(&mut self.buf, s.len() as u64);
        self.buf.extend_from_slice(s.as_bytes());
    }

    /// Writes a raw byte slice field (`WireBytes`).
    #[inline]
    pub fn write_bytes(&mut self, field_num: u32, b: &[u8]) {
        self.write_tag(field_num, WIRE_BYTES);
        append_varint(&mut self.buf, b.len() as u64);
        self.buf.extend_from_slice(b);
    }

    /// Writes a `WireArray(WireString)` field.
    pub fn write_string_arr<S: AsRef<str>>(&mut self, field_num: u32, items: &[S]) {
        self.write_tag(field_num, WIRE_ARRAY);
        let pos = self.buf.len();
        self.buf.extend_from_slice(&[0, 0, WIRE_STRING]);
        append_varint(&mut self.buf, items.len() as u64);
        for item in items {
            let s = item.as_ref();
            append_varint(&mut self.buf, s.len() as u64);
            self.buf.extend_from_slice(s.as_bytes());
        }
        backpatch_container_len(&mut self.buf, pos);
    }

    /// Writes a `WireArray(WireUint)` field from `u32` values.
    pub fn write_uint32_arr(&mut self, field_num: u32, items: &[u32]) {
        self.write_tag(field_num, WIRE_ARRAY);
        let pos = self.buf.len();
        self.buf.extend_from_slice(&[0, 0, WIRE_UINT]);
        append_varint(&mut self.buf, items.len() as u64);
        for &v in items {
            append_varint(&mut self.buf, u64::from(v));
        }
        backpatch_container_len(&mut self.buf, pos);
    }

    /// Writes a `WireMap<WireString, WireUint>` field.
    pub fn write_map_string_uint(
        &mut self,
        field_num: u32,
        m: &HashMap<String, u64>,
        deterministic: bool,
    ) {
        self.write_tag(field_num, WIRE_MAP);
        encode_map_string_uint(&mut self.buf, m, deterministic);
    }
}

// ============================================================================
// Zero-Copy Streaming Decoder
// ============================================================================

/// Zero-copy cursor over an OmniBuf byte slice `&'a [u8]`.
#[derive(Clone, Copy, Debug)]
pub struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
    depth: usize,
    rem_alloc: usize,
}

impl<'a> Decoder<'a> {
    /// Creates a new root `Decoder` over `data` at nesting depth `0`.
    #[inline]
    pub const fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            depth: 0,
            rem_alloc: usize::MAX,
        }
    }

    /// Creates a root `Decoder` bounded by `max_alloc_bytes`.
    #[inline]
    pub const fn with_max_alloc(data: &'a [u8], max_alloc_bytes: usize) -> Self {
        Self {
            data,
            pos: 0,
            depth: 0,
            rem_alloc: max_alloc_bytes,
        }
    }

    /// Creates a nested `Decoder` over `data` at `depth`, enforcing `MAX_NESTING_DEPTH`.
    #[inline]
    pub fn with_depth(data: &'a [u8], depth: usize) -> Result<Self> {
        if depth > MAX_NESTING_DEPTH {
            return Err(Error::DepthLimitExceeded(depth));
        }
        Ok(Self {
            data,
            pos: 0,
            depth,
            rem_alloc: usize::MAX,
        })
    }

    /// Creates a nested `Decoder` over `data` at `depth` bounded by `rem_alloc` bytes.
    #[inline]
    pub fn with_depth_and_alloc(data: &'a [u8], depth: usize, rem_alloc: usize) -> Result<Self> {
        if depth > MAX_NESTING_DEPTH {
            return Err(Error::DepthLimitExceeded(depth));
        }
        Ok(Self {
            data,
            pos: 0,
            depth,
            rem_alloc,
        })
    }

    /// Returns the remaining allocation budget tracked by this decoder (`usize::MAX` when unbounded).
    #[inline]
    pub const fn remaining_alloc(&self) -> usize {
        self.rem_alloc
    }

    /// Charges `bytes` against this decoder's remaining allocation budget.
    #[inline]
    pub fn charge_alloc(&mut self, bytes: usize) -> Result<()> {
        if self.rem_alloc == usize::MAX {
            return Ok(());
        }
        if bytes > self.rem_alloc {
            return Err(cold_parse_err("allocation budget exceeds max_alloc_bytes"));
        }
        self.rem_alloc -= bytes;
        Ok(())
    }

    /// Returns `true` when all bytes in the buffer have been consumed.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Returns the current byte offset in the underlying slice.
    #[inline]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Advances or resets the current byte offset in the underlying slice.
    #[inline]
    pub fn set_position(&mut self, pos: usize) {
        self.pos = pos;
    }

    /// Returns the current container nesting depth.
    #[inline]
    pub const fn depth(&self) -> usize {
        self.depth
    }

    /// Returns the full underlying slice.
    #[inline]
    pub const fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Reads the next raw tag `(field_num << 4) | wire_type`, or `Ok(None)` at clean EOF.
    #[inline]
    pub fn next_raw_tag(&mut self) -> Result<Option<u64>> {
        let n = self.data.len();
        if self.pos >= n {
            return Ok(None);
        }
        let b0 = self.data[self.pos];
        if (b0 & 1) != 0 {
            self.pos += 1;
            return Ok(Some(u64::from(b0 >> 1)));
        }
        if (b0 & 2) != 0 && self.pos + 2 <= n {
            let raw: [u8; 2] = self.data[self.pos..self.pos + 2].try_into().unwrap();
            self.pos += 2;
            return Ok(Some(u64::from(u16::from_le_bytes(raw) >> 2)));
        }
        self.next_raw_tag_slow()
    }

    #[cold]
    #[inline(never)]
    fn next_raw_tag_slow(&mut self) -> Result<Option<u64>> {
        let (tag, tn) = decode_varint(&self.data[self.pos..])
            .ok_or_else(|| cold_parse_err("invalid or truncated tag"))?;
        if (tag >> 4) > MAX_FIELD_NUMBER {
            return Err(cold_parse_err("field number exceeds maximum 29-bit limit"));
        }
        self.pos += tn;
        Ok(Some(tag))
    }

    /// Reads the next `(field_num, wire_type)` pair, or `Ok(None)` at clean EOF.
    #[inline(always)]
    pub fn next_tag(&mut self) -> Result<Option<(u32, u8)>> {
        let n = self.data.len();
        if self.pos >= n {
            return Ok(None);
        }
        let b0 = self.data[self.pos];
        if (b0 & 1) != 0 {
            self.pos += 1;
            return Ok(Some((u32::from(b0 >> 5), (b0 >> 1) & 0x0F)));
        }
        if (b0 & 2) != 0 && self.pos + 2 <= n {
            let raw: [u8; 2] = self.data[self.pos..self.pos + 2].try_into().unwrap();
            self.pos += 2;
            let u = u16::from_le_bytes(raw) >> 2;
            return Ok(Some((u32::from(u >> 4), (u & 0x0F) as u8)));
        }
        let Some(tag) = self.next_raw_tag_slow()? else {
            return Ok(None);
        };
        Ok(Some(((tag >> 4) as u32, (tag & 0x0F) as u8)))
    }

    /// Reads an unsigned `Prefix-Varint` payload.
    #[inline(always)]
    pub fn read_uint(&mut self) -> Result<u64> {
        let (v, next_pos) = read_varint_at(self.data, self.pos)?;
        self.pos = next_pos;
        Ok(v)
    }

    /// Reads a ZigZag-encoded signed `Prefix-Varint` payload.
    #[inline]
    pub fn read_sint(&mut self) -> Result<i64> {
        self.read_uint().map(decode_zigzag)
    }

    /// Reads a 4-byte little-endian `u32`.
    #[inline]
    pub fn read_fixed32(&mut self) -> Result<u32> {
        let end = self
            .pos
            .checked_add(4)
            .ok_or_else(|| cold_parse_err("truncated fixed32"))?;
        let raw: [u8; 4] = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| cold_parse_err("truncated fixed32"))?
            .try_into()
            .unwrap();
        self.pos = end;
        Ok(u32::from_le_bytes(raw))
    }

    /// Reads an 8-byte little-endian `u64`.
    #[inline]
    pub fn read_fixed64(&mut self) -> Result<u64> {
        let end = self
            .pos
            .checked_add(8)
            .ok_or_else(|| cold_parse_err("truncated fixed64"))?;
        let raw: [u8; 8] = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| cold_parse_err("truncated fixed64"))?
            .try_into()
            .unwrap();
        self.pos = end;
        Ok(u64::from_le_bytes(raw))
    }

    /// Reads a 4-byte little-endian `i32`.
    #[inline]
    pub fn read_sfixed32(&mut self) -> Result<i32> {
        self.read_fixed32().map(|v| v as i32)
    }

    /// Reads an 8-byte little-endian `i64`.
    #[inline]
    pub fn read_sfixed64(&mut self) -> Result<i64> {
        self.read_fixed64().map(|v| v as i64)
    }

    /// Reads a 4-byte IEEE-754 `f32`.
    #[inline]
    pub fn read_float32(&mut self) -> Result<f32> {
        self.read_fixed32().map(f32::from_bits)
    }

    /// Reads an 8-byte IEEE-754 `f64`.
    #[inline]
    pub fn read_float64(&mut self) -> Result<f64> {
        self.read_fixed64().map(f64::from_bits)
    }

    /// Reads a zero-copy UTF-8 `&'a str` slice directly from the input buffer.
    #[inline]
    pub fn read_str(&mut self) -> Result<&'a str> {
        let (s, next_pos) = read_str_slice(self.data, self.pos)?;
        self.pos = next_pos;
        Ok(s)
    }

    /// Reads a zero-copy `&'a [u8]` byte slice directly from the input buffer.
    #[inline]
    pub fn read_bytes(&mut self) -> Result<&'a [u8]> {
        let (b, next_pos) = read_len_slice(self.data, self.pos, 0)?;
        self.pos = next_pos;
        Ok(b)
    }

    /// Reads a length-prefixed container slice with at least `min_len` bytes.
    #[inline]
    pub fn read_container(&mut self, min_len: usize) -> Result<&'a [u8]> {
        let (b, next_pos) = read_len_slice(self.data, self.pos, min_len)?;
        self.pos = next_pos;
        Ok(b)
    }

    /// Validates and skips a `Field #0` (`SchemaMeta`) block in place.
    #[inline]
    pub fn skip_field0(&mut self) -> Result<()> {
        self.pos = validate_field0(self.data, self.pos, self.depth)?;
        Ok(())
    }

    /// Validates and skips an unknown or mismatched field value at the current nesting depth.
    #[inline]
    pub fn skip_unknown(&mut self, fnum: u32, wt: u8) -> Result<()> {
        if fnum == 0 {
            if wt != WIRE_SUB_MSG {
                return Err(Error::parse(format!("invalid Field #0 wire type {wt}")));
            }
            return self.skip_field0();
        }
        self.pos = validate_value(self.data, self.pos, wt, self.depth)?;
        Ok(())
    }
}
