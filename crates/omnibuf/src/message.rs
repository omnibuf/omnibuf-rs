use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::Hash;

use crate::error::{Error, Result};
use crate::field0::SchemaMeta;
use crate::wire::{
    MAX_NESTING_DEPTH, WIRE_ARRAY, WIRE_BOOL_FALSE, WIRE_BOOL_TRUE, WIRE_BYTES, WIRE_FIXED32,
    WIRE_FIXED64, WIRE_FLOAT32, WIRE_FLOAT64, WIRE_MAP, WIRE_SFIXED32, WIRE_SFIXED64, WIRE_SINT,
    WIRE_STRING, WIRE_SUB_MSG, WIRE_UINT, append_tag, append_varint, backpatch_container_len,
    decode_varint, decode_zigzag, encode_zigzag, grow_capacity, parse_array_header,
    parse_map_header, read_len_slice, read_str_slice,
};

/// Options controlling OmniBuf serialization.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EncodeOptions {
    /// Sorts `WireMap` keys in ascending order so identical messages always produce
    /// byte-for-byte identical wire output.
    pub deterministic: bool,
    /// Emits `Field #0` (`Tag = 0x19`, `WireSubMsg = 12`, `omnibuf.v1.SchemaMeta`)
    /// at byte 0 of the root message with declared field names and child schemas.
    pub self_describing: bool,
}

impl EncodeOptions {
    /// Returns options with deterministic map key ordering enabled.
    #[inline]
    pub const fn deterministic() -> Self {
        Self {
            deterministic: true,
            self_describing: false,
        }
    }

    /// Returns options with `Field #0` (`SchemaMeta`) emission and deterministic map ordering enabled.
    #[inline]
    pub const fn self_describing() -> Self {
        Self {
            deterministic: true,
            self_describing: true,
        }
    }
}

/// Trait implemented by Rust types that serialize and deserialize in OmniBuf wire format.
pub trait Message: Default + Sized {
    /// Appends the OmniBuf wire representation of `self` to `dst`.
    fn encode_omnibuf_append(&self, dst: &mut Vec<u8>, deterministic: bool) -> Result<()>;

    /// Decodes `data` into `self` at recursion `depth`.
    ///
    /// When `merge` is `false`, fields absent from `data` are reset to their default values.
    fn decode_omnibuf_at_depth(&mut self, data: &[u8], depth: usize, merge: bool) -> Result<()>;

    /// Resets all fields of `self` to their default values.
    fn clear_omnibuf(&mut self);

    /// Builds the `Field #0` [`SchemaMeta`] descriptor for `Self`, using `active` and `depth`
    /// to bound recursive message graphs.
    fn build_schema_meta(active: &mut HashSet<&'static str>, depth: usize) -> Option<SchemaMeta>;

    /// Returns the root [`SchemaMeta`] for `Self`.
    fn schema_meta() -> SchemaMeta {
        let mut active = HashSet::new();
        Self::build_schema_meta(&mut active, 0).unwrap_or_default()
    }

    /// Encodes `self` into a newly allocated `Vec<u8>`.
    #[inline]
    fn encode_omnibuf(&self) -> Result<Vec<u8>> {
        self.encode_omnibuf_with_options(EncodeOptions::default())
    }

    /// Encodes `self` with deterministic map key ordering.
    #[inline]
    fn encode_omnibuf_deterministic(&self) -> Result<Vec<u8>> {
        self.encode_omnibuf_with_options(EncodeOptions::deterministic())
    }

    /// Appends `self` to `dst` using explicit [`EncodeOptions`].
    #[inline]
    fn encode_omnibuf_with_options_append(
        &self,
        dst: &mut Vec<u8>,
        opts: EncodeOptions,
    ) -> Result<()> {
        if opts.self_describing {
            let meta = Self::schema_meta();
            meta.append_field0(dst);
        }
        self.encode_omnibuf_append(dst, opts.deterministic)
    }

    /// Encodes `self` into a newly allocated `Vec<u8>` using explicit [`EncodeOptions`].
    #[inline]
    fn encode_omnibuf_with_options(&self, opts: EncodeOptions) -> Result<Vec<u8>> {
        let mut dst = Vec::with_capacity(512);
        self.encode_omnibuf_with_options_append(&mut dst, opts)?;
        Ok(dst)
    }

    /// Decodes `data` into `self`, resetting any unseen fields.
    #[inline]
    fn decode_omnibuf(&mut self, data: &[u8]) -> Result<()> {
        self.decode_omnibuf_at_depth(data, 0, false)
    }

    /// Allocates a default instance of `Self` and decodes `data` into it.
    #[inline]
    fn from_omnibuf(data: &[u8]) -> Result<Self> {
        let mut msg = Self::default();
        msg.decode_omnibuf(data)?;
        Ok(msg)
    }
}

/// Encodes `msg` into a new `Vec<u8>`.
#[inline]
pub fn to_vec<M: Message>(msg: &M) -> Result<Vec<u8>> {
    msg.encode_omnibuf()
}

/// Encodes `msg` into a new `Vec<u8>` with deterministic `WireMap` key ordering.
#[inline]
pub fn to_vec_deterministic<M: Message>(msg: &M) -> Result<Vec<u8>> {
    msg.encode_omnibuf_deterministic()
}

/// Encodes `msg` into a new `Vec<u8>` with explicit [`EncodeOptions`].
#[inline]
pub fn to_vec_with_options<M: Message>(msg: &M, opts: EncodeOptions) -> Result<Vec<u8>> {
    msg.encode_omnibuf_with_options(opts)
}

/// Decodes an OmniBuf byte slice into a newly allocated `M`.
#[inline]
pub fn from_slice<M: Message>(data: &[u8]) -> Result<M> {
    M::from_omnibuf(data)
}

/// Decodes an OmniBuf byte slice into an existing `dst` instance, clearing absent fields.
#[inline]
pub fn decode_into<M: Message>(data: &[u8], dst: &mut M) -> Result<()> {
    dst.decode_omnibuf(data)
}

/// Low-level codec primitives invoked by `#[derive(OmniBuf)]` and `protoc-gen-omnibuf-rs`.
pub mod codec {
    use super::*;

    /// Checks whether a field value is considered zero/empty when `omitempty` is enabled.
    pub trait IsEmpty {
        fn is_omnibuf_empty(&self) -> bool;
    }

    macro_rules! impl_int_is_empty {
        ($($t:ty),*) => {
            $(
                impl IsEmpty for $t {
                    #[inline]
                    fn is_omnibuf_empty(&self) -> bool {
                        *self == 0
                    }
                }
            )*
        };
    }

    impl_int_is_empty!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize);

    impl IsEmpty for bool {
        #[inline]
        fn is_omnibuf_empty(&self) -> bool {
            !*self
        }
    }

    impl IsEmpty for f32 {
        #[inline]
        fn is_omnibuf_empty(&self) -> bool {
            self.to_bits() == 0
        }
    }

    impl IsEmpty for f64 {
        #[inline]
        fn is_omnibuf_empty(&self) -> bool {
            self.to_bits() == 0
        }
    }

    impl IsEmpty for String {
        #[inline]
        fn is_omnibuf_empty(&self) -> bool {
            self.is_empty()
        }
    }

    impl<T> IsEmpty for Vec<T> {
        #[inline]
        fn is_omnibuf_empty(&self) -> bool {
            self.is_empty()
        }
    }

    impl<T> IsEmpty for Option<T> {
        #[inline]
        fn is_omnibuf_empty(&self) -> bool {
            self.is_none()
        }
    }

    impl<T: IsEmpty> IsEmpty for Box<T> {
        #[inline]
        fn is_omnibuf_empty(&self) -> bool {
            (**self).is_omnibuf_empty()
        }
    }

    impl<K, V, S> IsEmpty for HashMap<K, V, S> {
        #[inline]
        fn is_omnibuf_empty(&self) -> bool {
            self.is_empty()
        }
    }

    impl<K, V> IsEmpty for BTreeMap<K, V> {
        #[inline]
        fn is_omnibuf_empty(&self) -> bool {
            self.is_empty()
        }
    }

    #[inline]
    pub fn write_uint_field(dst: &mut Vec<u8>, field_num: u32, v: u64) {
        append_tag(dst, field_num, WIRE_UINT);
        append_varint(dst, v);
    }

    #[inline]
    pub fn write_sint_field(dst: &mut Vec<u8>, field_num: u32, v: i64) {
        append_tag(dst, field_num, WIRE_SINT);
        append_varint(dst, encode_zigzag(v));
    }

    #[inline]
    pub fn write_bool_field(dst: &mut Vec<u8>, field_num: u32, v: bool) {
        append_tag(
            dst,
            field_num,
            if v { WIRE_BOOL_TRUE } else { WIRE_BOOL_FALSE },
        );
    }

    #[inline]
    pub fn write_fixed32_field(dst: &mut Vec<u8>, field_num: u32, v: u32) {
        append_tag(dst, field_num, WIRE_FIXED32);
        dst.extend_from_slice(&v.to_le_bytes());
    }

    #[inline]
    pub fn write_fixed64_field(dst: &mut Vec<u8>, field_num: u32, v: u64) {
        append_tag(dst, field_num, WIRE_FIXED64);
        dst.extend_from_slice(&v.to_le_bytes());
    }

    #[inline]
    pub fn write_sfixed32_field(dst: &mut Vec<u8>, field_num: u32, v: i32) {
        append_tag(dst, field_num, WIRE_SFIXED32);
        dst.extend_from_slice(&v.to_le_bytes());
    }

    #[inline]
    pub fn write_sfixed64_field(dst: &mut Vec<u8>, field_num: u32, v: i64) {
        append_tag(dst, field_num, WIRE_SFIXED64);
        dst.extend_from_slice(&v.to_le_bytes());
    }

    #[inline]
    pub fn write_float32_field(dst: &mut Vec<u8>, field_num: u32, v: f32) {
        append_tag(dst, field_num, WIRE_FLOAT32);
        dst.extend_from_slice(&v.to_bits().to_le_bytes());
    }

    #[inline]
    pub fn write_float64_field(dst: &mut Vec<u8>, field_num: u32, v: f64) {
        append_tag(dst, field_num, WIRE_FLOAT64);
        dst.extend_from_slice(&v.to_bits().to_le_bytes());
    }

    #[inline]
    pub fn write_string_field(dst: &mut Vec<u8>, field_num: u32, s: &str) {
        append_tag(dst, field_num, WIRE_STRING);
        append_varint(dst, s.len() as u64);
        dst.extend_from_slice(s.as_bytes());
    }

    #[inline]
    pub fn write_bytes_field(dst: &mut Vec<u8>, field_num: u32, b: &[u8]) {
        append_tag(dst, field_num, WIRE_BYTES);
        append_varint(dst, b.len() as u64);
        dst.extend_from_slice(b);
    }

    #[inline]
    pub fn write_sub_msg_field<M: Message>(
        dst: &mut Vec<u8>,
        field_num: u32,
        msg: &M,
        deterministic: bool,
    ) -> Result<()> {
        append_tag(dst, field_num, WIRE_SUB_MSG);
        let len_pos = dst.len();
        dst.extend_from_slice(&[0, 0]);
        msg.encode_omnibuf_append(dst, deterministic)?;
        backpatch_container_len(dst, len_pos);
        Ok(())
    }

    #[inline]
    pub fn read_sub_msg_field<M: Message>(
        msg: &mut M,
        data: &[u8],
        pos: usize,
        depth: usize,
        merge: bool,
    ) -> Result<usize> {
        let (sub_bytes, next_pos) = read_len_slice(data, pos, 0)?;
        msg.decode_omnibuf_at_depth(sub_bytes, depth + 1, merge)?;
        Ok(next_pos)
    }

    #[inline]
    pub fn read_opt_sub_msg_field<M: Message>(
        slot: &mut Option<M>,
        data: &[u8],
        pos: usize,
        depth: usize,
        merge: bool,
    ) -> Result<usize> {
        let (sub_bytes, next_pos) = read_len_slice(data, pos, 0)?;
        let msg = slot.get_or_insert_with(M::default);
        msg.decode_omnibuf_at_depth(sub_bytes, depth + 1, merge)?;
        Ok(next_pos)
    }

    #[inline]
    pub fn read_opt_box_sub_msg_field<M: Message>(
        slot: &mut Option<Box<M>>,
        data: &[u8],
        pos: usize,
        depth: usize,
        merge: bool,
    ) -> Result<usize> {
        let (sub_bytes, next_pos) = read_len_slice(data, pos, 0)?;
        let msg = slot.get_or_insert_with(|| Box::new(M::default()));
        msg.decode_omnibuf_at_depth(sub_bytes, depth + 1, merge)?;
        Ok(next_pos)
    }

    /// Encodes a `WireArray` of scalar elements using `write_elem`.
    #[inline]
    pub fn write_scalar_vec_field<T, F>(
        dst: &mut Vec<u8>,
        field_num: u32,
        elem_wt: u8,
        items: &[T],
        mut write_elem: F,
    ) -> Result<()>
    where
        F: FnMut(&mut Vec<u8>, &T) -> Result<()>,
    {
        append_tag(dst, field_num, WIRE_ARRAY);
        let len_pos = dst.len();
        dst.extend_from_slice(&[0, 0, elem_wt]);
        append_varint(dst, items.len() as u64);
        for item in items {
            write_elem(dst, item)?;
        }
        backpatch_container_len(dst, len_pos);
        Ok(())
    }

    /// Decodes a `WireArray` of scalar elements using `read_elem`.
    #[inline]
    pub fn read_scalar_vec_field<T, F>(
        items: &mut Vec<T>,
        data: &[u8],
        pos: usize,
        depth: usize,
        exp_elem_wt: u8,
        reset: bool,
        mut read_elem: F,
    ) -> Result<usize>
    where
        F: FnMut(&[u8], usize) -> Result<(T, usize)>,
    {
        if depth + 1 > MAX_NESTING_DEPTH {
            return Err(Error::DepthLimitExceeded(depth + 1));
        }
        let (body, next_pos) = read_len_slice(data, pos, 2)?;
        if reset {
            items.clear();
        }
        let (elem_wt, count, mut p) =
            parse_array_header(body).ok_or_else(|| Error::parse("invalid WireArray header"))?;
        if elem_wt != exp_elem_wt {
            return Err(Error::parse("WireArray element wire type mismatch"));
        }
        let total = items.len() + count;
        if items.capacity() < total {
            items.reserve(grow_capacity(items.capacity(), total) - items.len());
        }
        for _ in 0..count {
            let (val, next_p) = read_elem(body, p)?;
            items.push(val);
            p = next_p;
        }
        if p != body.len() {
            return Err(Error::parse("WireArray trailing bytes"));
        }
        Ok(next_pos)
    }

    /// Encodes `Vec<M>` as `WireArray(WireSubMsg)`.
    #[inline]
    pub fn write_sub_msg_vec_field<M: Message>(
        dst: &mut Vec<u8>,
        field_num: u32,
        items: &[M],
        deterministic: bool,
    ) -> Result<()> {
        append_tag(dst, field_num, WIRE_ARRAY);
        let len_pos = dst.len();
        dst.extend_from_slice(&[0, 0, WIRE_SUB_MSG]);
        append_varint(dst, items.len() as u64);
        for item in items {
            let elem_pos = dst.len();
            dst.extend_from_slice(&[0, 0]);
            item.encode_omnibuf_append(dst, deterministic)?;
            backpatch_container_len(dst, elem_pos);
        }
        backpatch_container_len(dst, len_pos);
        Ok(())
    }

    /// Encodes `Vec<Box<M>>` as `WireArray(WireSubMsg)`.
    #[inline]
    pub fn write_box_sub_msg_vec_field<M: Message>(
        dst: &mut Vec<u8>,
        field_num: u32,
        items: &[Box<M>],
        deterministic: bool,
    ) -> Result<()> {
        append_tag(dst, field_num, WIRE_ARRAY);
        let len_pos = dst.len();
        dst.extend_from_slice(&[0, 0, WIRE_SUB_MSG]);
        append_varint(dst, items.len() as u64);
        for item in items {
            let elem_pos = dst.len();
            dst.extend_from_slice(&[0, 0]);
            item.encode_omnibuf_append(dst, deterministic)?;
            backpatch_container_len(dst, elem_pos);
        }
        backpatch_container_len(dst, len_pos);
        Ok(())
    }

    /// Decodes `WireArray(WireSubMsg)` into `Vec<M>`.
    #[inline]
    pub fn read_sub_msg_vec_field<M: Message>(
        items: &mut Vec<M>,
        data: &[u8],
        pos: usize,
        depth: usize,
        reset: bool,
    ) -> Result<usize> {
        if depth + 1 > MAX_NESTING_DEPTH {
            return Err(Error::DepthLimitExceeded(depth + 1));
        }
        let (body, next_pos) = read_len_slice(data, pos, 2)?;
        if reset {
            items.clear();
        }
        let (elem_wt, count, mut p) =
            parse_array_header(body).ok_or_else(|| Error::parse("invalid WireArray header"))?;
        if elem_wt != WIRE_SUB_MSG {
            return Err(Error::parse("expected WireArray(WireSubMsg)"));
        }
        let total = items.len() + count;
        if items.capacity() < total {
            items.reserve(grow_capacity(items.capacity(), total) - items.len());
        }
        for _ in 0..count {
            let (elem_bytes, next_p) = read_len_slice(body, p, 0)?;
            let mut elem = M::default();
            elem.decode_omnibuf_at_depth(elem_bytes, depth + 2, false)?;
            items.push(elem);
            p = next_p;
        }
        if p != body.len() {
            return Err(Error::parse("WireArray(WireSubMsg) trailing bytes"));
        }
        Ok(next_pos)
    }

    /// Decodes `WireArray(WireSubMsg)` into `Vec<Box<M>>`.
    pub fn read_box_sub_msg_vec_field<M: Message>(
        items: &mut Vec<Box<M>>,
        data: &[u8],
        pos: usize,
        depth: usize,
        reset: bool,
    ) -> Result<usize> {
        if depth + 1 > MAX_NESTING_DEPTH {
            return Err(Error::DepthLimitExceeded(depth + 1));
        }
        let (body, next_pos) = read_len_slice(data, pos, 2)?;
        if reset {
            items.clear();
        }
        let (elem_wt, count, mut p) =
            parse_array_header(body).ok_or_else(|| Error::parse("invalid WireArray header"))?;
        if elem_wt != WIRE_SUB_MSG {
            return Err(Error::parse(format!(
                "expected WireArray(WireSubMsg), got element type {elem_wt}"
            )));
        }
        let total = items.len() + count;
        if items.capacity() < total {
            items.reserve(grow_capacity(items.capacity(), total) - items.len());
        }
        for _ in 0..count {
            let (elem_bytes, next_p) = read_len_slice(body, p, 0)?;
            let mut elem = Box::new(M::default());
            elem.decode_omnibuf_at_depth(elem_bytes, depth + 2, false)?;
            items.push(elem);
            p = next_p;
        }
        if p != body.len() {
            return Err(Error::parse("WireArray(WireSubMsg) trailing bytes"));
        }
        Ok(next_pos)
    }

    // ========================================================================
    // Scalar Element Payload Helpers (Inside WireArray & WireMap)
    // ========================================================================

    #[inline]
    pub fn read_elem_uint(body: &[u8], p: usize) -> Result<(u64, usize)> {
        let (v, vn) = decode_varint(
            body.get(p..)
                .ok_or_else(|| Error::parse("uint offset out of bounds"))?,
        )
        .ok_or_else(|| Error::parse(format!("truncated uint element at {p}")))?;
        Ok((v, p + vn))
    }

    #[inline]
    pub fn read_elem_sint(body: &[u8], p: usize) -> Result<(i64, usize)> {
        let (v, next_p) = read_elem_uint(body, p)?;
        Ok((decode_zigzag(v), next_p))
    }

    #[inline]
    pub fn read_elem_bool(body: &[u8], p: usize) -> Result<(bool, usize)> {
        let b = *body
            .get(p)
            .ok_or_else(|| Error::parse(format!("truncated bool element at {p}")))?;
        match b {
            0 => Ok((false, p + 1)),
            1 => Ok((true, p + 1)),
            _ => Err(Error::parse(format!("invalid bool byte {b} at {p}"))),
        }
    }

    #[inline]
    pub fn read_elem_fixed32(body: &[u8], p: usize) -> Result<(u32, usize)> {
        let raw: [u8; 4] = body
            .get(p..p + 4)
            .ok_or_else(|| Error::parse(format!("truncated fixed32 element at {p}")))?
            .try_into()
            .unwrap();
        Ok((u32::from_le_bytes(raw), p + 4))
    }

    #[inline]
    pub fn read_elem_fixed64(body: &[u8], p: usize) -> Result<(u64, usize)> {
        let raw: [u8; 8] = body
            .get(p..p + 8)
            .ok_or_else(|| Error::parse(format!("truncated fixed64 element at {p}")))?
            .try_into()
            .unwrap();
        Ok((u64::from_le_bytes(raw), p + 8))
    }

    #[inline]
    pub fn read_elem_sfixed32(body: &[u8], p: usize) -> Result<(i32, usize)> {
        let (v, next_p) = read_elem_fixed32(body, p)?;
        Ok((v as i32, next_p))
    }

    #[inline]
    pub fn read_elem_sfixed64(body: &[u8], p: usize) -> Result<(i64, usize)> {
        let (v, next_p) = read_elem_fixed64(body, p)?;
        Ok((v as i64, next_p))
    }

    #[inline]
    pub fn read_elem_float32(body: &[u8], p: usize) -> Result<(f32, usize)> {
        let (v, next_p) = read_elem_fixed32(body, p)?;
        Ok((f32::from_bits(v), next_p))
    }

    #[inline]
    pub fn read_elem_float64(body: &[u8], p: usize) -> Result<(f64, usize)> {
        let (v, next_p) = read_elem_fixed64(body, p)?;
        Ok((f64::from_bits(v), next_p))
    }

    #[inline]
    pub fn read_elem_string(body: &[u8], p: usize) -> Result<(String, usize)> {
        let (s, next_p) = read_str_slice(body, p)?;
        Ok((s.to_owned(), next_p))
    }

    #[inline]
    pub fn read_elem_bytes(body: &[u8], p: usize) -> Result<(Vec<u8>, usize)> {
        let (b, next_p) = read_len_slice(body, p, 0)?;
        Ok((b.to_vec(), next_p))
    }

    // ========================================================================
    // Generic WireMap Encoding & Decoding (HashMap & BTreeMap)
    // ========================================================================

    /// Encodes a `HashMap<K, V>` as a `WireMap` field, sorting keys via `Ord` when `deterministic` is `true`.
    #[allow(clippy::too_many_arguments)]
    pub fn write_hash_map_field<K, V, S, FK, FV>(
        dst: &mut Vec<u8>,
        field_num: u32,
        key_wt: u8,
        val_wt: u8,
        map: &HashMap<K, V, S>,
        deterministic: bool,
        mut write_key: FK,
        mut write_val: FV,
    ) -> Result<()>
    where
        K: Ord,
        FK: FnMut(&mut Vec<u8>, &K) -> Result<()>,
        FV: FnMut(&mut Vec<u8>, &V, bool) -> Result<()>,
    {
        append_tag(dst, field_num, WIRE_MAP);
        let len_pos = dst.len();
        dst.extend_from_slice(&[0, 0, key_wt, val_wt]);
        append_varint(dst, map.len() as u64);
        if deterministic && map.len() > 1 {
            let mut entries: Vec<(&K, &V)> = map.iter().collect();
            entries.sort_unstable_by(|(ka, _), (kb, _)| ka.cmp(kb));
            for (k, v) in entries {
                write_key(dst, k)?;
                write_val(dst, v, deterministic)?;
            }
        } else {
            for (k, v) in map {
                write_key(dst, k)?;
                write_val(dst, v, deterministic)?;
            }
        }
        backpatch_container_len(dst, len_pos);
        Ok(())
    }

    /// Encodes a `BTreeMap<K, V>` as a `WireMap` field (keys are already in ascending `Ord` order).
    #[allow(clippy::too_many_arguments)]
    pub fn write_btree_map_field<K, V, FK, FV>(
        dst: &mut Vec<u8>,
        field_num: u32,
        key_wt: u8,
        val_wt: u8,
        map: &BTreeMap<K, V>,
        deterministic: bool,
        mut write_key: FK,
        mut write_val: FV,
    ) -> Result<()>
    where
        FK: FnMut(&mut Vec<u8>, &K) -> Result<()>,
        FV: FnMut(&mut Vec<u8>, &V, bool) -> Result<()>,
    {
        append_tag(dst, field_num, WIRE_MAP);
        let len_pos = dst.len();
        dst.extend_from_slice(&[0, 0, key_wt, val_wt]);
        append_varint(dst, map.len() as u64);
        for (k, v) in map {
            write_key(dst, k)?;
            write_val(dst, v, deterministic)?;
        }
        backpatch_container_len(dst, len_pos);
        Ok(())
    }

    /// Decodes a `WireMap` field into a `HashMap<K, V>`.
    #[allow(clippy::too_many_arguments)]
    pub fn read_hash_map_field<K, V, S, FK, FV>(
        map: &mut HashMap<K, V, S>,
        data: &[u8],
        pos: usize,
        depth: usize,
        exp_key_wt: u8,
        exp_val_wt: u8,
        reset: bool,
        mut read_key: FK,
        mut read_val: FV,
    ) -> Result<usize>
    where
        K: Eq + Hash,
        S: Default + std::hash::BuildHasher,
        FK: FnMut(&[u8], usize) -> Result<(K, usize)>,
        FV: FnMut(&[u8], usize, usize) -> Result<(V, usize)>,
    {
        if depth + 1 > MAX_NESTING_DEPTH {
            return Err(Error::DepthLimitExceeded(depth + 1));
        }
        let (body, next_pos) = read_len_slice(data, pos, 3)?;
        let (key_wt, val_wt, count, mut p) =
            parse_map_header(body).ok_or_else(|| Error::parse("invalid WireMap header"))?;
        if key_wt != exp_key_wt || val_wt != exp_val_wt {
            return Err(Error::parse(format!(
                "WireMap header mismatch: expected ({exp_key_wt}, {exp_val_wt}), got ({key_wt}, {val_wt})"
            )));
        }
        if reset {
            map.clear();
        }
        map.reserve(count.min(4096));
        for _ in 0..count {
            let (k, after_k) = read_key(body, p)?;
            let (v, after_v) = read_val(body, after_k, depth + 1)?;
            map.insert(k, v);
            p = after_v;
        }
        if p != body.len() {
            return Err(Error::parse("WireMap trailing bytes"));
        }
        Ok(next_pos)
    }

    /// Decodes a `WireMap` field into a `BTreeMap<K, V>`.
    #[allow(clippy::too_many_arguments)]
    pub fn read_btree_map_field<K, V, FK, FV>(
        map: &mut BTreeMap<K, V>,
        data: &[u8],
        pos: usize,
        depth: usize,
        exp_key_wt: u8,
        exp_val_wt: u8,
        reset: bool,
        mut read_key: FK,
        mut read_val: FV,
    ) -> Result<usize>
    where
        K: Ord,
        FK: FnMut(&[u8], usize) -> Result<(K, usize)>,
        FV: FnMut(&[u8], usize, usize) -> Result<(V, usize)>,
    {
        if depth + 1 > MAX_NESTING_DEPTH {
            return Err(Error::DepthLimitExceeded(depth + 1));
        }
        let (body, next_pos) = read_len_slice(data, pos, 3)?;
        let (key_wt, val_wt, count, mut p) =
            parse_map_header(body).ok_or_else(|| Error::parse("invalid WireMap header"))?;
        if key_wt != exp_key_wt || val_wt != exp_val_wt {
            return Err(Error::parse(format!(
                "WireMap header mismatch: expected ({exp_key_wt}, {exp_val_wt}), got ({key_wt}, {val_wt})"
            )));
        }
        if reset {
            map.clear();
        }
        for _ in 0..count {
            let (k, after_k) = read_key(body, p)?;
            let (v, after_v) = read_val(body, after_k, depth + 1)?;
            map.insert(k, v);
            p = after_v;
        }
        if p != body.len() {
            return Err(Error::parse("WireMap trailing bytes"));
        }
        Ok(next_pos)
    }
}
