use core::any::TypeId;
use core::cell::Cell;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::Hash;

use crate::error::{Error, Result};
use crate::field0::{SchemaMeta, validate_field0_with_alloc};
use crate::wire::{
    MAX_FIELD_NUMBER, MAX_NESTING_DEPTH, WIRE_ARRAY, WIRE_BOOL_FALSE, WIRE_BOOL_TRUE, WIRE_BYTES,
    WIRE_EXTENDED, WIRE_FIXED32, WIRE_FIXED64, WIRE_FLOAT32, WIRE_FLOAT64, WIRE_MAP, WIRE_SFIXED32,
    WIRE_SFIXED64, WIRE_SINT, WIRE_STRING, WIRE_SUB_MSG, WIRE_UINT, append_bytes_elem, append_tag,
    append_varint, backpatch_container_len, backpatch_container_len_4b, backpatch_container_len_9b,
    backpatch_container_len_fast, bytes_to_owned_utf8, bytes_to_owned_vec, cold_parse_err,
    container_len_width, copy_bytes_fast, decode_varint, decode_zigzag, encode_zigzag,
    fast_skip_value, grow_capacity, parse_array_header, parse_array_header_typed, parse_map_header,
    put_varint_raw, read_container_slice, read_container_slice_opt, read_len_slice,
    read_len_slice_opt, read_str_slice, read_varint_at, read_varint_at_opt, varint_len,
    write_bool_tagged, write_bytes_tagged, write_fixed_tagged, write_varint_tagged,
};

static ACTIVE_BUDGET_GUARDS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static ACTIVE_TYPED_ALLOC_REM: Cell<usize> = const { Cell::new(usize::MAX) };
}

pub(crate) struct AllocBudgetGuard {
    prev: usize,
}

impl AllocBudgetGuard {
    #[inline]
    pub(crate) fn new(limit: usize) -> Self {
        ACTIVE_BUDGET_GUARDS.fetch_add(1, Ordering::Relaxed);
        let prev = ACTIVE_TYPED_ALLOC_REM.with(|c| c.replace(limit));
        Self { prev }
    }
}

impl Drop for AllocBudgetGuard {
    #[inline]
    fn drop(&mut self) {
        ACTIVE_TYPED_ALLOC_REM.with(|c| c.set(self.prev));
        ACTIVE_BUDGET_GUARDS.fetch_sub(1, Ordering::Relaxed);
    }
}

#[inline(always)]
pub(crate) fn charge_typed_alloc(bytes: usize) -> Result<()> {
    if bytes == 0 || ACTIVE_BUDGET_GUARDS.load(Ordering::Relaxed) == 0 {
        return Ok(());
    }
    charge_typed_alloc_slow(bytes)
}

#[cold]
#[inline(never)]
fn charge_typed_alloc_slow(bytes: usize) -> Result<()> {
    ACTIVE_TYPED_ALLOC_REM.with(|c| {
        let rem = c.get();
        if rem == usize::MAX {
            return Ok(());
        }
        if bytes > rem {
            return Err(cold_parse_err("allocation budget exceeds max_alloc_bytes"));
        }
        c.set(rem - bytes);
        Ok(())
    })
}

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

/// Resource limits enforced when decoding untrusted OmniBuf packets (Spec §10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeOptions {
    /// Maximum allowed input packet byte length (`default = 64 MiB`).
    pub max_message_bytes: usize,
    /// Maximum cumulative container element count across arrays and maps (`default = 4,194,304`).
    pub max_elements: usize,
    /// Maximum cumulative allocation budget for strings, byte slices, and container slots (`default = 64 MiB`).
    pub max_alloc_bytes: usize,
    /// Maximum allowed sub-message and container nesting depth (`default = MAX_NESTING_DEPTH = 32`).
    pub max_depth: usize,
}

impl DecodeOptions {
    /// Returns the default safe decoding limits.
    #[inline]
    pub const fn default_limits() -> Self {
        Self {
            max_message_bytes: 64 * 1024 * 1024,
            max_elements: 4 * 1024 * 1024,
            max_alloc_bytes: 64 * 1024 * 1024,
            max_depth: MAX_NESTING_DEPTH,
        }
    }
}

impl Default for DecodeOptions {
    #[inline]
    fn default() -> Self {
        Self::default_limits()
    }
}

#[derive(Default)]
struct BudgetTracker {
    elements: usize,
    alloc_bytes: usize,
    precharged_bytes: usize,
}

impl BudgetTracker {
    #[inline]
    fn add_elements(&mut self, count: usize, opts: &DecodeOptions) -> Result<()> {
        self.elements = self
            .elements
            .checked_add(count)
            .ok_or_else(|| Error::parse("element count budget overflow"))?;
        if self.elements > opts.max_elements {
            return Err(Error::parse(format!(
                "container element count {} exceeds max_elements {}",
                self.elements, opts.max_elements
            )));
        }
        Ok(())
    }

    #[inline]
    fn add_alloc(&mut self, bytes: usize, opts: &DecodeOptions) -> Result<()> {
        self.alloc_bytes = self
            .alloc_bytes
            .checked_add(bytes)
            .ok_or_else(|| Error::parse("allocation budget overflow"))?;
        if self.alloc_bytes > opts.max_alloc_bytes {
            return Err(Error::parse(format!(
                "allocation budget {} exceeds max_alloc_bytes {}",
                self.alloc_bytes, opts.max_alloc_bytes
            )));
        }
        Ok(())
    }
}

/// Validates `data` against explicit [`DecodeOptions`] resource limits before materializing values,
/// returning pre-charged schema allocation bytes.
pub(crate) fn enforce_decode_options_with_schema_alloc(
    data: &[u8],
    opts: &DecodeOptions,
) -> Result<usize> {
    if data.len() > opts.max_message_bytes {
        return Err(Error::parse(format!(
            "message length {} exceeds max_message_bytes {}",
            data.len(),
            opts.max_message_bytes
        )));
    }
    let effective_depth = opts.max_depth.min(MAX_NESTING_DEPTH);
    let mut tracker = BudgetTracker::default();
    validate_message_with_limits(data, 0, effective_depth, opts, &mut tracker)?;
    Ok(tracker.precharged_bytes)
}

fn validate_message_with_limits(
    data: &[u8],
    depth: usize,
    max_depth: usize,
    opts: &DecodeOptions,
    tracker: &mut BudgetTracker,
) -> Result<()> {
    if depth > max_depth {
        return Err(Error::DepthLimitExceeded(depth));
    }
    let mut pos = 0usize;
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
            let (end, est_alloc) = validate_field0_with_alloc(data, pos, depth, max_depth)?;
            let charged = end.saturating_sub(pos).max(est_alloc);
            tracker.add_alloc(charged, opts)?;
            tracker.precharged_bytes = tracker.precharged_bytes.saturating_add(charged);
            pos = end;
        } else {
            pos = validate_value_with_limits(data, pos, wt, depth, max_depth, opts, tracker)?;
        }
    }
    Ok(())
}

fn validate_value_with_limits(
    data: &[u8],
    pos: usize,
    wt: u8,
    depth: usize,
    max_depth: usize,
    opts: &DecodeOptions,
    tracker: &mut BudgetTracker,
) -> Result<usize> {
    if depth > max_depth {
        return Err(Error::DepthLimitExceeded(depth));
    }
    match wt {
        WIRE_STRING => {
            let (s, end) = read_str_slice(data, pos)?;
            tracker.add_alloc(s.len(), opts)?;
            tracker.precharged_bytes = tracker.precharged_bytes.saturating_add(s.len());
            Ok(end)
        }
        WIRE_BYTES => {
            let (b, end) = read_len_slice(data, pos, 0)?;
            tracker.add_alloc(b.len(), opts)?;
            tracker.precharged_bytes = tracker.precharged_bytes.saturating_add(b.len());
            Ok(end)
        }
        WIRE_SUB_MSG => {
            let (body, end) = read_len_slice(data, pos, 0)?;
            validate_message_with_limits(body, depth + 1, max_depth, opts, tracker)?;
            Ok(end)
        }
        WIRE_ARRAY => {
            if depth + 1 > max_depth {
                return Err(Error::DepthLimitExceeded(depth + 1));
            }
            let (body, end) = read_len_slice(data, pos, 2)?;
            let (elem_wt, count, mut p) =
                parse_array_header(body).ok_or_else(|| Error::parse("invalid array header"))?;
            tracker.add_elements(count, opts)?;
            tracker.add_alloc(count.saturating_mul(8), opts)?;
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
                    return Ok(end);
                }
                WIRE_FIXED32 | WIRE_SFIXED32 | WIRE_FLOAT32 => {
                    if body.len() - p != count.saturating_mul(4) {
                        return Err(Error::parse("invalid 32-bit array length"));
                    }
                    return Ok(end);
                }
                WIRE_FIXED64 | WIRE_SFIXED64 | WIRE_FLOAT64 => {
                    if body.len() - p != count.saturating_mul(8) {
                        return Err(Error::parse("invalid 64-bit array length"));
                    }
                    return Ok(end);
                }
                _ => {}
            }
            for _ in 0..count {
                p = validate_entry_with_limits(
                    body,
                    p,
                    elem_wt,
                    depth + 1,
                    max_depth,
                    opts,
                    tracker,
                )?;
            }
            if p != body.len() {
                return Err(Error::parse("trailing array bytes"));
            }
            Ok(end)
        }
        WIRE_MAP => {
            if depth + 1 > max_depth {
                return Err(Error::DepthLimitExceeded(depth + 1));
            }
            let (body, end) = read_len_slice(data, pos, 3)?;
            let (key_wt, val_wt, count, mut p) =
                parse_map_header(body).ok_or_else(|| Error::parse("invalid map header"))?;
            tracker.add_elements(count, opts)?;
            tracker.add_alloc(count.saturating_mul(24), opts)?;
            for _ in 0..count {
                p = validate_entry_with_limits(
                    body,
                    p,
                    key_wt,
                    depth + 1,
                    max_depth,
                    opts,
                    tracker,
                )?;
                p = validate_entry_with_limits(
                    body,
                    p,
                    val_wt,
                    depth + 1,
                    max_depth,
                    opts,
                    tracker,
                )?;
            }
            if p != body.len() {
                return Err(Error::parse("trailing map bytes"));
            }
            Ok(end)
        }
        WIRE_EXTENDED => {
            let (b, end) = read_len_slice(data, pos, 1)?;
            tracker.add_alloc(b.len(), opts)?;
            Ok(end)
        }
        _ => fast_skip_value(data, pos, wt)
            .ok_or_else(|| Error::parse(format!("truncated or invalid wireType {wt} at {pos}"))),
    }
}

fn validate_entry_with_limits(
    body: &[u8],
    p: usize,
    wt: u8,
    depth: usize,
    max_depth: usize,
    opts: &DecodeOptions,
    tracker: &mut BudgetTracker,
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
    validate_value_with_limits(body, p, wt, depth, max_depth, opts, tracker)
}

/// Trait implemented by Rust types that serialize and deserialize in OmniBuf wire format.
pub trait Message: Default + Sized + 'static {
    /// Whether `Self` contains any nested sub-message, array, map, or oneof fields.
    ///
    /// Leaf structs containing only scalar, string, or bytes fields set this to `false`
    /// so container writers can skip redundant `min_wire_size()` pre-scans.
    const HAS_NESTED_CONTAINERS: bool = true;

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
    fn build_schema_meta(active: &mut HashSet<TypeId>, depth: usize) -> Option<SchemaMeta>;

    /// Returns `true` if `Self` or any reachable child sub-message schema contains a recursion cycle.
    fn is_schema_cyclic(active: &mut HashSet<TypeId>, depth: usize) -> bool {
        let _ = (active, depth);
        false
    }

    /// Builds an instance-aware [`SchemaMeta`] for `self` at `depth`, expanding populated
    /// recursive sub-message values up to `MAX_NESTING_DEPTH`.
    fn build_value_schema_meta(&self, depth: usize) -> Option<SchemaMeta> {
        let mut active = HashSet::new();
        Self::build_schema_meta(&mut active, depth)
    }

    /// Returns the root [`SchemaMeta`] for `Self`.
    fn schema_meta() -> SchemaMeta {
        let mut active = HashSet::new();
        Self::build_schema_meta(&mut active, 1).unwrap_or_default()
    }

    /// Returns a strict lower bound on the encoded byte length of `self` (bounded by `depth_rem`).
    #[inline]
    fn min_wire_size_bounded(&self, depth_rem: usize) -> usize {
        let _ = depth_rem;
        0
    }

    /// Returns a strict lower bound on the encoded byte length of `self`.
    #[inline]
    fn min_wire_size(&self) -> usize {
        self.min_wire_size_bounded(4)
    }

    /// Returns a fast byte-length estimate used to pre-size encode buffers and container headers.
    #[inline]
    fn encoded_size_hint(&self) -> usize {
        let min = self.min_wire_size();
        min.saturating_add((min >> 6).clamp(64, 512))
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
            let mut active = HashSet::new();
            let meta = if Self::is_schema_cyclic(&mut active, 1) {
                self.build_value_schema_meta(1).unwrap_or_default()
            } else {
                Self::schema_meta()
            };
            meta.append_field0(dst)?;
        }
        self.encode_omnibuf_append(dst, opts.deterministic)
    }

    /// Encodes `self` into a newly allocated `Vec<u8>` using explicit [`EncodeOptions`].
    #[inline]
    fn encode_omnibuf_with_options(&self, opts: EncodeOptions) -> Result<Vec<u8>> {
        let extra = if opts.self_describing { 256 } else { 16 };
        let cap = self.encoded_size_hint().saturating_add(extra);
        let mut dst = Vec::with_capacity(cap);
        self.encode_omnibuf_with_options_append(&mut dst, opts)?;
        Ok(dst)
    }

    /// Decodes `data` into `self`, resetting any unseen fields.
    #[inline(always)]
    fn decode_omnibuf(&mut self, data: &[u8]) -> Result<()> {
        self.decode_omnibuf_at_depth(data, 0, false)
    }

    /// Decodes `data` into `self` while enforcing explicit [`DecodeOptions`] resource limits.
    #[inline]
    fn decode_omnibuf_with_options(&mut self, data: &[u8], opts: DecodeOptions) -> Result<()> {
        let schema_alloc = enforce_decode_options_with_schema_alloc(data, &opts)?;
        let _guard = AllocBudgetGuard::new(opts.max_alloc_bytes.saturating_sub(schema_alloc));
        self.decode_omnibuf_at_depth(data, 0, false)
    }

    /// Allocates a default instance of `Self` and decodes `data` into it.
    #[inline(always)]
    fn from_omnibuf(data: &[u8]) -> Result<Self> {
        let mut msg = Self::default();
        msg.decode_omnibuf_at_depth(data, 0, true)?;
        Ok(msg)
    }

    /// Allocates a default instance of `Self` and decodes `data` under explicit [`DecodeOptions`].
    #[inline]
    fn from_omnibuf_with_options(data: &[u8], opts: DecodeOptions) -> Result<Self> {
        let schema_alloc = enforce_decode_options_with_schema_alloc(data, &opts)?;
        let _guard = AllocBudgetGuard::new(opts.max_alloc_bytes.saturating_sub(schema_alloc));
        let mut msg = Self::default();
        msg.decode_omnibuf_at_depth(data, 0, true)?;
        Ok(msg)
    }
}

/// Trait implemented by zero-copy borrowed view types that decode directly from `&'de [u8]`
/// without allocating `String` or `Vec<u8>` buffers for scalar UTF-8 and byte fields.
pub trait DecodeBorrowed<'de>: Default + Sized {
    /// Decodes `data` into `self` at recursion `depth`, borrowing `&'de str` and `&'de [u8]`
    /// slices directly from `data`.
    fn decode_omnibuf_borrowed_at_depth(
        &mut self,
        data: &'de [u8],
        depth: usize,
        merge: bool,
    ) -> Result<()>;

    /// Resets all fields of `self` to their default values.
    #[inline]
    fn clear_omnibuf_borrowed(&mut self) {
        *self = Self::default();
    }

    /// Decodes `data` into `self`, resetting unseen fields.
    #[inline]
    fn decode_omnibuf_borrowed(&mut self, data: &'de [u8]) -> Result<()> {
        self.decode_omnibuf_borrowed_at_depth(data, 0, false)
    }

    /// Decodes `data` into `self` while enforcing explicit [`DecodeOptions`] resource limits.
    #[inline]
    fn decode_omnibuf_borrowed_with_options(
        &mut self,
        data: &'de [u8],
        opts: DecodeOptions,
    ) -> Result<()> {
        let schema_alloc = enforce_decode_options_with_schema_alloc(data, &opts)?;
        let _guard = AllocBudgetGuard::new(opts.max_alloc_bytes.saturating_sub(schema_alloc));
        self.decode_omnibuf_borrowed_at_depth(data, 0, false)
    }

    /// Decodes `data` into a newly constructed zero-copy borrowed `Self`.
    #[inline]
    fn from_omnibuf_borrowed(data: &'de [u8]) -> Result<Self> {
        let mut view = Self::default();
        view.decode_omnibuf_borrowed_at_depth(data, 0, true)?;
        Ok(view)
    }

    /// Decodes `data` into a newly constructed zero-copy borrowed `Self` under [`DecodeOptions`].
    #[inline]
    fn from_omnibuf_borrowed_with_options(data: &'de [u8], opts: DecodeOptions) -> Result<Self> {
        let schema_alloc = enforce_decode_options_with_schema_alloc(data, &opts)?;
        let _guard = AllocBudgetGuard::new(opts.max_alloc_bytes.saturating_sub(schema_alloc));
        let mut view = Self::default();
        view.decode_omnibuf_borrowed_at_depth(data, 0, true)?;
        Ok(view)
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
#[inline(always)]
pub fn from_slice<M: Message>(data: &[u8]) -> Result<M> {
    M::from_omnibuf(data)
}

/// Decodes an OmniBuf byte slice into `M` while enforcing explicit [`DecodeOptions`].
#[inline]
pub fn from_slice_with_options<M: Message>(data: &[u8], opts: DecodeOptions) -> Result<M> {
    M::from_omnibuf_with_options(data, opts)
}

/// Decodes an OmniBuf byte slice into a zero-copy borrowed `M: DecodeBorrowed<'de>`.
#[inline]
pub fn from_slice_borrowed<'de, M: DecodeBorrowed<'de>>(data: &'de [u8]) -> Result<M> {
    M::from_omnibuf_borrowed(data)
}

/// Decodes an OmniBuf byte slice into a zero-copy borrowed `M` under [`DecodeOptions`].
#[inline]
pub fn from_slice_borrowed_with_options<'de, M: DecodeBorrowed<'de>>(
    data: &'de [u8],
    opts: DecodeOptions,
) -> Result<M> {
    M::from_omnibuf_borrowed_with_options(data, opts)
}

/// Decodes an OmniBuf byte slice into an existing borrowed `dst` view, clearing absent fields.
#[inline]
pub fn decode_into_borrowed<'de, M: DecodeBorrowed<'de>>(
    data: &'de [u8],
    dst: &mut M,
) -> Result<()> {
    dst.decode_omnibuf_borrowed(data)
}

/// Decodes an OmniBuf byte slice into an existing borrowed `dst` view under [`DecodeOptions`].
#[inline]
pub fn decode_into_borrowed_with_options<'de, M: DecodeBorrowed<'de>>(
    data: &'de [u8],
    dst: &mut M,
    opts: DecodeOptions,
) -> Result<()> {
    dst.decode_omnibuf_borrowed_with_options(data, opts)
}

/// Decodes an OmniBuf byte slice into an existing `dst` instance, clearing absent fields.
#[inline]
pub fn decode_into<M: Message>(data: &[u8], dst: &mut M) -> Result<()> {
    dst.decode_omnibuf(data)
}

/// Decodes an OmniBuf byte slice into `dst` while enforcing explicit [`DecodeOptions`].
#[inline]
pub fn decode_into_with_options<M: Message>(
    data: &[u8],
    dst: &mut M,
    opts: DecodeOptions,
) -> Result<()> {
    dst.decode_omnibuf_with_options(data, opts)
}

/// Low-level codec primitives invoked by `#[derive(OmniBuf)]` and `protoc-gen-omnibuf-rs`.
pub mod codec {
    use super::*;

    /// Trait implemented by `#[derive(OmniBuf)]` on Protobuf/OmniBuf `oneof` enums.
    pub trait Oneof: Sized + 'static {
        /// Appends the active oneof variant's tagged field to `dst`.
        fn encode_oneof(&self, dst: &mut Vec<u8>, deterministic: bool) -> Result<()>;

        /// Returns a strict lower bound on the encoded byte size for the active oneof arm.
        #[inline]
        fn min_wire_size_bounded(&self, depth_rem: usize) -> usize {
            let _ = depth_rem;
            0
        }

        /// Returns an estimated encoded byte size for the active oneof arm.
        #[inline]
        fn encoded_size_hint(&self) -> usize {
            self.min_wire_size_bounded(4).max(16)
        }

        /// Attempts to decode field `(fnum, wt)` at `data[pos..]` into `slot`.
        ///
        /// Returns `Ok(Some(next_pos))` when `(fnum, wt)` matched one of this oneof's arms
        /// with its expected wire type, or `Ok(None)` when `(fnum, wt)` was not handled.
        fn decode_oneof_arm(
            slot: &mut Option<Self>,
            fnum: u32,
            wt: u8,
            data: &[u8],
            pos: usize,
            depth: usize,
        ) -> Result<Option<usize>>;

        /// Registers all variant field numbers and names of this oneof into `meta.fields`.
        fn register_schema_fields(meta: &mut SchemaMeta);

        /// Registers sub-message children of this oneof into `meta.children`.
        fn register_schema_meta(meta: &mut SchemaMeta, active: &mut HashSet<TypeId>, depth: usize);

        /// Returns `true` if any sub-message variant of this oneof introduces a schema cycle.
        fn is_schema_cyclic(active: &mut HashSet<TypeId>, depth: usize) -> bool {
            let _ = (active, depth);
            false
        }

        /// Registers the active sub-message variant's value-driven [`SchemaMeta`] into `meta.children`.
        fn register_value_schema_meta(&self, meta: &mut SchemaMeta, depth: usize) {
            let _ = (meta, depth);
        }
    }

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

    /// Single-reserve raw-pointer writer for contiguous runs of flat scalar, string, and bytes fields.
    ///
    /// Amortizes capacity checks and `Vec::len` updates across a run of fields while keeping
    /// all caller-facing write methods safe.
    pub struct RawBufWriter<'a> {
        dst: &'a mut Vec<u8>,
        ptr: *mut u8,
        end: *mut u8,
    }

    impl<'a> RawBufWriter<'a> {
        /// Reserves at least `max_bytes` of spare capacity in `dst` and initializes a raw write cursor.
        #[inline(always)]
        pub fn new(dst: &'a mut Vec<u8>, max_bytes: usize) -> Self {
            let len = dst.len();
            if dst.capacity() - len < max_bytes {
                dst.reserve(max_bytes);
            }
            let cap = dst.capacity();
            let base = dst.as_mut_ptr();
            // SAFETY: `len <= cap` always holds for any `Vec<u8>`.
            unsafe {
                Self {
                    dst,
                    ptr: base.add(len),
                    end: base.add(cap),
                }
            }
        }

        /// Commits all written bytes back to `dst.len()`.
        #[inline(always)]
        pub fn finish(self) {
            // SAFETY: `self.ptr` was derived from `self.dst.as_mut_ptr()` and only advanced
            // over initialized bytes within `self.dst`'s capacity.
            unsafe {
                let new_len = self.ptr.offset_from(self.dst.as_ptr()) as usize;
                self.dst.set_len(new_len);
            }
        }

        #[cold]
        #[inline(never)]
        fn grow_cold(&mut self, needed: usize) {
            // SAFETY: `self.ptr` is within `self.dst`'s allocation and every byte before `self.ptr`
            // has been initialized.
            unsafe {
                let written = self.ptr.offset_from(self.dst.as_ptr()) as usize;
                self.dst.set_len(written);
                self.dst.reserve(needed);
                let base = self.dst.as_mut_ptr();
                self.ptr = base.add(written);
                self.end = base.add(self.dst.capacity());
            }
        }

        #[inline(always)]
        fn ensure(&mut self, needed: usize) {
            if (self.end as usize).wrapping_sub(self.ptr as usize) < needed {
                self.grow_cold(needed);
            }
        }

        /// Writes `tag` at `self.ptr`, advancing `self.ptr` by `varint_len(tag)`.
        ///
        /// # Safety
        /// At least `varint_len(tag)` writable bytes must remain at `self.ptr`.
        #[inline(always)]
        unsafe fn write_tag_unchecked(&mut self, tag: u64) {
            // SAFETY: Caller guarantees at least `varint_len(tag)` writable bytes remain at `self.ptr`.
            unsafe {
                if tag <= 127 {
                    *self.ptr = ((tag as u8) << 1) | 1;
                    self.ptr = self.ptr.add(1);
                } else if tag <= 16_383 {
                    let u = ((tag as u16) << 2) | 2;
                    core::ptr::write_unaligned(self.ptr.cast::<u16>(), u.to_le());
                    self.ptr = self.ptr.add(2);
                } else if tag <= 536_870_911 {
                    let u = ((tag as u32) << 3) | 4;
                    core::ptr::write_unaligned(self.ptr.cast::<u32>(), u.to_le());
                    self.ptr = self.ptr.add(4);
                } else {
                    *self.ptr = 0;
                    core::ptr::write_unaligned(self.ptr.add(1).cast::<u64>(), tag.to_le());
                    self.ptr = self.ptr.add(9);
                }
            }
        }

        /// Writes a zero-payload boolean field tag.
        #[inline(always)]
        pub fn write_bool(&mut self, field_num: u32, v: bool) {
            let tf = (u64::from(field_num) << 4) | u64::from(WIRE_BOOL_FALSE);
            let tt = (u64::from(field_num) << 4) | u64::from(WIRE_BOOL_TRUE);
            if tt <= 127 {
                self.ensure(1);
                // SAFETY: `self.ensure(1)` guarantees at least 1 writable byte at `self.ptr`.
                unsafe {
                    *self.ptr = (((tf as u8) << 1) | 1) | ((u8::from(v)) << 1);
                    self.ptr = self.ptr.add(1);
                }
            } else if tt <= 16_383 {
                self.ensure(2);
                let u = if v {
                    ((tt as u16) << 2) | 2
                } else {
                    ((tf as u16) << 2) | 2
                };
                // SAFETY: `self.ensure(2)` guarantees at least 2 writable bytes at `self.ptr`.
                unsafe {
                    core::ptr::write_unaligned(self.ptr.cast::<u16>(), u.to_le());
                    self.ptr = self.ptr.add(2);
                }
            } else {
                let tag = if v { tt } else { tf };
                let tw = varint_len(tag);
                self.ensure(tw);
                // SAFETY: `self.ensure(tw)` guarantees `tw` writable bytes at `self.ptr`.
                unsafe {
                    self.write_tag_unchecked(tag);
                }
            }
        }

        #[inline(always)]
        fn write_varint_with_wt(&mut self, field_num: u32, wt: u8, v: u64) {
            let tag = (u64::from(field_num) << 4) | u64::from(wt);
            let tw = varint_len(tag);
            self.ensure(tw + 9);
            // SAFETY: `self.ensure(tw + 9)` guarantees `tw` tag bytes plus at least 9 varint bytes.
            unsafe {
                self.write_tag_unchecked(tag);
                let vn = put_varint_raw(self.ptr, v);
                self.ptr = self.ptr.add(vn);
            }
        }

        /// Writes a `WireUint` field.
        #[inline(always)]
        pub fn write_uint(&mut self, field_num: u32, v: u64) {
            self.write_varint_with_wt(field_num, WIRE_UINT, v);
        }

        /// Writes a `WireSint` (ZigZag-encoded) field.
        #[inline(always)]
        pub fn write_sint(&mut self, field_num: u32, v: i64) {
            self.write_varint_with_wt(field_num, WIRE_SINT, encode_zigzag(v));
        }

        #[inline(always)]
        fn write_fixed32_with_wt(&mut self, field_num: u32, wt: u8, v: u32) {
            let tag = (u64::from(field_num) << 4) | u64::from(wt);
            let tw = varint_len(tag);
            self.ensure(tw + 4);
            // SAFETY: `self.ensure(tw + 4)` guarantees `tw + 4` writable bytes at `self.ptr`.
            unsafe {
                self.write_tag_unchecked(tag);
                core::ptr::write_unaligned(self.ptr.cast::<u32>(), v.to_le());
                self.ptr = self.ptr.add(4);
            }
        }

        #[inline(always)]
        fn write_fixed64_with_wt(&mut self, field_num: u32, wt: u8, v: u64) {
            let tag = (u64::from(field_num) << 4) | u64::from(wt);
            let tw = varint_len(tag);
            self.ensure(tw + 8);
            // SAFETY: `self.ensure(tw + 8)` guarantees `tw + 8` writable bytes at `self.ptr`.
            unsafe {
                self.write_tag_unchecked(tag);
                core::ptr::write_unaligned(self.ptr.cast::<u64>(), v.to_le());
                self.ptr = self.ptr.add(8);
            }
        }

        /// Writes a `WireFixed32` field.
        #[inline(always)]
        pub fn write_fixed32(&mut self, field_num: u32, v: u32) {
            self.write_fixed32_with_wt(field_num, WIRE_FIXED32, v);
        }

        /// Writes a `WireFixed64` field.
        #[inline(always)]
        pub fn write_fixed64(&mut self, field_num: u32, v: u64) {
            self.write_fixed64_with_wt(field_num, WIRE_FIXED64, v);
        }

        /// Writes a `WireSfixed32` field.
        #[inline(always)]
        pub fn write_sfixed32(&mut self, field_num: u32, v: i32) {
            self.write_fixed32_with_wt(field_num, WIRE_SFIXED32, v as u32);
        }

        /// Writes a `WireSfixed64` field.
        #[inline(always)]
        pub fn write_sfixed64(&mut self, field_num: u32, v: i64) {
            self.write_fixed64_with_wt(field_num, WIRE_SFIXED64, v as u64);
        }

        /// Writes a `WireFloat32` field.
        #[inline(always)]
        pub fn write_float32(&mut self, field_num: u32, v: f32) {
            self.write_fixed32_with_wt(field_num, WIRE_FLOAT32, v.to_bits());
        }

        /// Writes a `WireFloat64` field.
        #[inline(always)]
        pub fn write_float64(&mut self, field_num: u32, v: f64) {
            self.write_fixed64_with_wt(field_num, WIRE_FLOAT64, v.to_bits());
        }

        #[inline(always)]
        fn write_bytes_with_wt(&mut self, field_num: u32, wt: u8, b: &[u8]) {
            let tag = (u64::from(field_num) << 4) | u64::from(wt);
            let tw = varint_len(tag);
            let blen = b.len();
            let needed = blen.checked_add(tw + 9).expect("capacity overflow");
            self.ensure(needed);
            // SAFETY: `self.ensure(tw + 9 + blen)` guarantees enough writable bytes for tag,
            // length varint, and payload; `b` is disjoint from `self.dst`.
            unsafe {
                self.write_tag_unchecked(tag);
                let dst_ptr = if blen <= 127 {
                    *self.ptr = ((blen as u8) << 1) | 1;
                    self.ptr.add(1)
                } else {
                    self.ptr.add(put_varint_raw(self.ptr, blen as u64))
                };
                copy_bytes_fast(b.as_ptr(), dst_ptr, blen);
                self.ptr = dst_ptr.add(blen);
            }
        }

        /// Writes a `WireString` field.
        #[inline(always)]
        pub fn write_string(&mut self, field_num: u32, s: &str) {
            self.write_bytes_with_wt(field_num, WIRE_STRING, s.as_bytes());
        }

        /// Writes a `WireBytes` field.
        #[inline(always)]
        pub fn write_bytes(&mut self, field_num: u32, b: &[u8]) {
            self.write_bytes_with_wt(field_num, WIRE_BYTES, b);
        }

        /// Writes a `buffa::EnumValue<E>` field as `WireSint`.
        #[cfg(feature = "buffa")]
        #[inline(always)]
        pub fn write_buffa_enum<E: ::buffa::Enumeration>(
            &mut self,
            field_num: u32,
            val: &::buffa::EnumValue<E>,
        ) {
            self.write_sint(field_num, i64::from(val.to_i32()));
        }
    }

    #[inline(always)]
    fn begin_tagged_container(dst: &mut Vec<u8>, field_num: u32, wire_type: u8) -> usize {
        let tag = (u64::from(field_num) << 4) | u64::from(wire_type & 0x0F);
        if tag <= 127 {
            let b0 = ((tag as u8) << 1) | 1;
            let len = dst.len();
            if dst.capacity() - len < 3 {
                dst.reserve(3);
            }
            // SAFETY: At least 3 writable bytes exist at `len`.
            unsafe {
                let ptr = dst.as_mut_ptr().add(len);
                *ptr = b0;
                *ptr.add(1) = 0;
                *ptr.add(2) = 0;
                dst.set_len(len + 3);
            }
            len + 1
        } else if tag <= 16_383 {
            let u = ((tag as u16) << 2) | 2;
            let len = dst.len();
            if dst.capacity() - len < 4 {
                dst.reserve(4);
            }
            // SAFETY: At least 4 writable bytes exist at `len`.
            unsafe {
                let ptr = dst.as_mut_ptr().add(len);
                core::ptr::write_unaligned(ptr.cast::<u16>(), u.to_le());
                *ptr.add(2) = 0;
                *ptr.add(3) = 0;
                dst.set_len(len + 4);
            }
            len + 2
        } else {
            append_tag(dst, field_num, wire_type);
            let len_pos = dst.len();
            dst.extend_from_slice(&[0, 0]);
            len_pos
        }
    }

    #[inline(always)]
    fn begin_tagged_container_4b(dst: &mut Vec<u8>, field_num: u32, wire_type: u8) -> usize {
        let tag = (u64::from(field_num) << 4) | u64::from(wire_type & 0x0F);
        if tag <= 127 {
            let b0 = ((tag as u8) << 1) | 1;
            let len_pos = dst.len() + 1;
            dst.extend_from_slice(&[b0, 0, 0, 0, 0]);
            len_pos
        } else if tag <= 16_383 {
            let tb = (((tag as u16) << 2) | 2).to_le_bytes();
            let len_pos = dst.len() + 2;
            dst.extend_from_slice(&[tb[0], tb[1], 0, 0, 0, 0]);
            len_pos
        } else {
            append_tag(dst, field_num, wire_type);
            let len_pos = dst.len();
            dst.extend_from_slice(&[0, 0, 0, 0]);
            len_pos
        }
    }

    #[inline(always)]
    fn begin_tagged_array(dst: &mut Vec<u8>, field_num: u32, elem_wt: u8, count: usize) -> usize {
        let tag = (u64::from(field_num) << 4) | u64::from(WIRE_ARRAY);
        let len = dst.len();
        if dst.capacity() - len < 21 {
            dst.reserve(21);
        }
        // SAFETY: At least 21 writable bytes exist at `len` (up to 9 tag bytes, 3 header bytes,
        // and up to 9 count varint bytes); all written bytes are initialized before `set_len`.
        unsafe {
            let ptr = dst.as_mut_ptr().add(len);
            let tn = put_varint_raw(ptr, tag);
            let len_pos = len + tn;
            *ptr.add(tn) = 0;
            *ptr.add(tn + 1) = 0;
            *ptr.add(tn + 2) = elem_wt;
            let cn = put_varint_raw(ptr.add(tn + 3), count as u64);
            dst.set_len(len + tn + 3 + cn);
            len_pos
        }
    }

    #[inline(always)]
    fn begin_tagged_array_4b(
        dst: &mut Vec<u8>,
        field_num: u32,
        elem_wt: u8,
        count: usize,
    ) -> usize {
        let tag = (u64::from(field_num) << 4) | u64::from(WIRE_ARRAY);
        dst.reserve(9 + 5 + 9);
        // SAFETY: `dst.reserve(23)` guarantees space for up to 9 tag bytes, 5 header bytes,
        // and up to 9 count varint bytes; all written bytes are initialized before `set_len`.
        unsafe {
            let len = dst.len();
            let ptr = dst.as_mut_ptr().add(len);
            let tn = put_varint_raw(ptr, tag);
            let len_pos = len + tn;
            *ptr.add(tn) = 0;
            *ptr.add(tn + 1) = 0;
            *ptr.add(tn + 2) = 0;
            *ptr.add(tn + 3) = 0;
            *ptr.add(tn + 4) = elem_wt;
            let cn = put_varint_raw(ptr.add(tn + 5), count as u64);
            dst.set_len(len + tn + 5 + cn);
            len_pos
        }
    }

    /// Writes a canonical container length header (minimum 2 bytes) directly at `ptr`, returning its width.
    ///
    /// # Safety
    /// `ptr` must be valid for writes of at least 9 bytes.
    #[inline(always)]
    unsafe fn put_container_len_raw(ptr: *mut u8, sub_len: usize) -> usize {
        // SAFETY: Caller guarantees `ptr` is valid for writes of at least 9 bytes.
        unsafe {
            if sub_len <= 16_383 {
                let u = ((sub_len as u16) << 2) | 2;
                core::ptr::copy_nonoverlapping(u.to_le_bytes().as_ptr(), ptr, 2);
                2
            } else if sub_len <= 536_870_911 {
                let u = ((sub_len as u32) << 3) | 4;
                core::ptr::copy_nonoverlapping(u.to_le_bytes().as_ptr(), ptr, 4);
                4
            } else {
                *ptr = 0;
                core::ptr::copy_nonoverlapping(
                    (sub_len as u64).to_le_bytes().as_ptr(),
                    ptr.add(1),
                    8,
                );
                9
            }
        }
    }

    /// Invokes `f` on a cold, non-inlined path so fallback decode loops never bloat hot functions.
    #[cold]
    #[inline(never)]
    pub fn cold_decode_fallback<F, R>(f: F) -> R
    where
        F: FnOnce() -> R,
    {
        f()
    }

    #[inline(always)]
    pub fn assign_str(slot: &mut String, s: &str) {
        if slot.capacity() == 0 {
            if !s.is_empty() {
                let n = s.len();
                let mut v = Vec::<u8>::with_capacity(n);
                // SAFETY: `v` has capacity `n`, `s` is valid UTF-8 and disjoint from `v`.
                unsafe {
                    copy_bytes_fast(s.as_ptr(), v.as_mut_ptr(), n);
                    v.set_len(n);
                    *slot = String::from_utf8_unchecked(v);
                }
            }
        } else {
            assign_str_reuse(slot, s);
        }
    }

    #[inline(never)]
    fn assign_str_reuse(slot: &mut String, s: &str) {
        slot.clear();
        slot.push_str(s);
    }

    #[inline(always)]
    pub fn assign_bytes(slot: &mut Vec<u8>, b: &[u8]) {
        if slot.capacity() == 0 {
            if !b.is_empty() {
                *slot = bytes_to_owned_vec(b);
            }
        } else {
            assign_bytes_reuse(slot, b);
        }
    }

    #[inline(never)]
    fn assign_bytes_reuse(slot: &mut Vec<u8>, b: &[u8]) {
        slot.clear();
        slot.extend_from_slice(b);
    }

    #[inline(always)]
    pub fn write_uint_field(dst: &mut Vec<u8>, field_num: u32, v: u64) {
        let tag = (u64::from(field_num) << 4) | u64::from(WIRE_UINT);
        if tag <= 127 {
            write_varint_tagged(dst, [((tag as u8) << 1) | 1], v);
        } else if tag <= 16_383 {
            let u = ((tag as u16) << 2) | 2;
            write_varint_tagged(dst, u.to_le_bytes(), v);
        } else {
            append_tag(dst, field_num, WIRE_UINT);
            append_varint(dst, v);
        }
    }

    #[inline(always)]
    pub fn write_sint_field(dst: &mut Vec<u8>, field_num: u32, v: i64) {
        let z = encode_zigzag(v);
        let tag = (u64::from(field_num) << 4) | u64::from(WIRE_SINT);
        if tag <= 127 {
            write_varint_tagged(dst, [((tag as u8) << 1) | 1], z);
        } else if tag <= 16_383 {
            let u = ((tag as u16) << 2) | 2;
            write_varint_tagged(dst, u.to_le_bytes(), z);
        } else {
            append_tag(dst, field_num, WIRE_SINT);
            append_varint(dst, z);
        }
    }

    #[inline(always)]
    pub fn write_bool_field(dst: &mut Vec<u8>, field_num: u32, v: bool) {
        let tf = (u64::from(field_num) << 4) | u64::from(WIRE_BOOL_FALSE);
        let tt = (u64::from(field_num) << 4) | u64::from(WIRE_BOOL_TRUE);
        if tt <= 127 {
            write_bool_tagged(dst, [((tf as u8) << 1) | 1], [((tt as u8) << 1) | 1], v);
        } else if tt <= 16_383 {
            write_bool_tagged(
                dst,
                (((tf as u16) << 2) | 2).to_le_bytes(),
                (((tt as u16) << 2) | 2).to_le_bytes(),
                v,
            );
        } else {
            append_tag(
                dst,
                field_num,
                if v { WIRE_BOOL_TRUE } else { WIRE_BOOL_FALSE },
            );
        }
    }

    #[inline(always)]
    pub fn write_fixed32_field(dst: &mut Vec<u8>, field_num: u32, v: u32) {
        let tag = (u64::from(field_num) << 4) | u64::from(WIRE_FIXED32);
        let bytes = v.to_le_bytes();
        if tag <= 127 {
            write_fixed_tagged(dst, [((tag as u8) << 1) | 1], bytes);
        } else if tag <= 16_383 {
            write_fixed_tagged(dst, (((tag as u16) << 2) | 2).to_le_bytes(), bytes);
        } else {
            append_tag(dst, field_num, WIRE_FIXED32);
            dst.extend_from_slice(&bytes);
        }
    }

    #[inline(always)]
    pub fn write_fixed64_field(dst: &mut Vec<u8>, field_num: u32, v: u64) {
        let tag = (u64::from(field_num) << 4) | u64::from(WIRE_FIXED64);
        let bytes = v.to_le_bytes();
        if tag <= 127 {
            write_fixed_tagged(dst, [((tag as u8) << 1) | 1], bytes);
        } else if tag <= 16_383 {
            write_fixed_tagged(dst, (((tag as u16) << 2) | 2).to_le_bytes(), bytes);
        } else {
            append_tag(dst, field_num, WIRE_FIXED64);
            dst.extend_from_slice(&bytes);
        }
    }

    #[inline(always)]
    pub fn write_sfixed32_field(dst: &mut Vec<u8>, field_num: u32, v: i32) {
        let tag = (u64::from(field_num) << 4) | u64::from(WIRE_SFIXED32);
        let bytes = v.to_le_bytes();
        if tag <= 127 {
            write_fixed_tagged(dst, [((tag as u8) << 1) | 1], bytes);
        } else if tag <= 16_383 {
            write_fixed_tagged(dst, (((tag as u16) << 2) | 2).to_le_bytes(), bytes);
        } else {
            append_tag(dst, field_num, WIRE_SFIXED32);
            dst.extend_from_slice(&bytes);
        }
    }

    #[inline(always)]
    pub fn write_sfixed64_field(dst: &mut Vec<u8>, field_num: u32, v: i64) {
        let tag = (u64::from(field_num) << 4) | u64::from(WIRE_SFIXED64);
        let bytes = v.to_le_bytes();
        if tag <= 127 {
            write_fixed_tagged(dst, [((tag as u8) << 1) | 1], bytes);
        } else if tag <= 16_383 {
            write_fixed_tagged(dst, (((tag as u16) << 2) | 2).to_le_bytes(), bytes);
        } else {
            append_tag(dst, field_num, WIRE_SFIXED64);
            dst.extend_from_slice(&bytes);
        }
    }

    #[inline(always)]
    pub fn write_float32_field(dst: &mut Vec<u8>, field_num: u32, v: f32) {
        let tag = (u64::from(field_num) << 4) | u64::from(WIRE_FLOAT32);
        let bytes = v.to_bits().to_le_bytes();
        if tag <= 127 {
            write_fixed_tagged(dst, [((tag as u8) << 1) | 1], bytes);
        } else if tag <= 16_383 {
            write_fixed_tagged(dst, (((tag as u16) << 2) | 2).to_le_bytes(), bytes);
        } else {
            append_tag(dst, field_num, WIRE_FLOAT32);
            dst.extend_from_slice(&bytes);
        }
    }

    #[inline(always)]
    pub fn write_float64_field(dst: &mut Vec<u8>, field_num: u32, v: f64) {
        let tag = (u64::from(field_num) << 4) | u64::from(WIRE_FLOAT64);
        let bytes = v.to_bits().to_le_bytes();
        if tag <= 127 {
            write_fixed_tagged(dst, [((tag as u8) << 1) | 1], bytes);
        } else if tag <= 16_383 {
            write_fixed_tagged(dst, (((tag as u16) << 2) | 2).to_le_bytes(), bytes);
        } else {
            append_tag(dst, field_num, WIRE_FLOAT64);
            dst.extend_from_slice(&bytes);
        }
    }

    #[inline(always)]
    pub fn write_string_field(dst: &mut Vec<u8>, field_num: u32, s: &str) {
        let tag = (u64::from(field_num) << 4) | u64::from(WIRE_STRING);
        let bytes = s.as_bytes();
        if tag <= 127 {
            write_bytes_tagged(dst, [((tag as u8) << 1) | 1], bytes);
        } else if tag <= 16_383 {
            write_bytes_tagged(dst, (((tag as u16) << 2) | 2).to_le_bytes(), bytes);
        } else {
            append_tag(dst, field_num, WIRE_STRING);
            append_bytes_elem(dst, bytes);
        }
    }

    #[inline(always)]
    pub fn write_bytes_field(dst: &mut Vec<u8>, field_num: u32, b: &[u8]) {
        let tag = (u64::from(field_num) << 4) | u64::from(WIRE_BYTES);
        if tag <= 127 {
            write_bytes_tagged(dst, [((tag as u8) << 1) | 1], b);
        } else if tag <= 16_383 {
            write_bytes_tagged(dst, (((tag as u16) << 2) | 2).to_le_bytes(), b);
        } else {
            append_tag(dst, field_num, WIRE_BYTES);
            append_bytes_elem(dst, b);
        }
    }

    #[inline(always)]
    pub fn write_sub_msg_field<M: Message>(
        dst: &mut Vec<u8>,
        field_num: u32,
        msg: &M,
        deterministic: bool,
    ) -> Result<()> {
        if M::HAS_NESTED_CONTAINERS && dst.capacity() > 16_383 {
            let min_body = msg.min_wire_size();
            if min_body > 16_383 {
                dst.reserve(min_body.saturating_add(16));
                let len_pos = begin_tagged_container_4b(dst, field_num, WIRE_SUB_MSG);
                msg.encode_omnibuf_append(dst, deterministic)?;
                backpatch_container_len_4b(dst, len_pos);
                return Ok(());
            }
        }
        let len_pos = begin_tagged_container(dst, field_num, WIRE_SUB_MSG);
        msg.encode_omnibuf_append(dst, deterministic)?;
        // SAFETY: `begin_tagged_container` appended the 2-byte length slot at `len_pos`.
        unsafe { backpatch_container_len_fast(dst, len_pos) };
        Ok(())
    }

    #[inline(always)]
    pub fn read_sub_msg_field<M: Message>(
        msg: &mut M,
        data: &[u8],
        pos: usize,
        depth: usize,
        merge: bool,
    ) -> Result<usize> {
        let (sub_bytes, next_pos) = read_container_slice(data, pos, 0)?;
        msg.decode_omnibuf_at_depth(sub_bytes, depth + 1, merge)?;
        Ok(next_pos)
    }

    #[inline(never)]
    fn decode_existing_sub_msg<M: Message>(
        msg: &mut M,
        sub_bytes: &[u8],
        depth: usize,
        merge: bool,
    ) -> Result<()> {
        msg.decode_omnibuf_at_depth(sub_bytes, depth, merge)
    }

    #[inline(always)]
    pub fn read_opt_sub_msg_field<M: Message>(
        slot: &mut Option<M>,
        data: &[u8],
        pos: usize,
        depth: usize,
        merge: bool,
    ) -> Result<usize> {
        let (sub_bytes, next_pos) = read_container_slice(data, pos, 0)?;
        match slot {
            None => {
                let mut msg = M::default();
                msg.decode_omnibuf_at_depth(sub_bytes, depth + 1, true)?;
                *slot = Some(msg);
            }
            Some(msg) => {
                decode_existing_sub_msg(msg, sub_bytes, depth + 1, merge)?;
            }
        }
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
        let (sub_bytes, next_pos) = read_container_slice(data, pos, 0)?;
        match slot {
            Some(msg) => msg.decode_omnibuf_at_depth(sub_bytes, depth + 1, merge)?,
            None => {
                super::charge_typed_alloc(core::mem::size_of::<M>())?;
                let mut msg = Box::new(M::default());
                msg.decode_omnibuf_at_depth(sub_bytes, depth + 1, true)?;
                *slot = Some(msg);
            }
        }
        Ok(next_pos)
    }

    /// Allocates and decodes a `Box<M>` from a `WireSubMsg` body, charging `size_of::<M>()`
    /// against the active `DecodeOptions::max_alloc_bytes` budget.
    #[inline]
    pub fn read_box_sub_msg_value<M: Message>(sub_bytes: &[u8], depth: usize) -> Result<Box<M>> {
        super::charge_typed_alloc(core::mem::size_of::<M>())?;
        let mut msg = Box::new(M::default());
        msg.decode_omnibuf_at_depth(sub_bytes, depth, true)?;
        Ok(msg)
    }

    /// Encodes a `WireArray` of varint-encoded scalar elements using exact size pre-computation.
    #[inline]
    pub fn write_varint_vec_field<T, F>(
        dst: &mut Vec<u8>,
        field_num: u32,
        elem_wt: u8,
        items: &[T],
        mut to_u64: F,
    ) -> Result<()>
    where
        F: FnMut(&T) -> u64,
    {
        let tag = (u64::from(field_num) << 4) | u64::from(WIRE_ARRAY);
        let count = items.len();
        if count <= 32 {
            let mut vals = [0u64; 32];
            let mut payload_bytes = 0usize;
            for (slot, item) in vals[..count].iter_mut().zip(items.iter()) {
                let v = to_u64(item);
                *slot = v;
                payload_bytes += varint_len(v);
            }
            let cn = varint_len(count as u64);
            let sub_len = 1 + cn + payload_bytes;
            let lw = container_len_width(sub_len);
            let tw = varint_len(tag);
            let exact = tw + lw + sub_len;
            dst.reserve(exact + 8);
            // SAFETY: `dst.reserve(exact + 8)` guarantees at least `exact + 8` writable bytes
            // at `start_len` (including 8 bytes of slack for the final `put_varint_raw` call),
            // and the sequence writes exactly `exact` bytes before `set_len`.
            unsafe {
                let start_len = dst.len();
                let mut ptr = dst.as_mut_ptr().add(start_len);
                ptr = ptr.add(put_varint_raw(ptr, tag));
                ptr = ptr.add(put_container_len_raw(ptr, sub_len));
                *ptr = elem_wt;
                ptr = ptr.add(1);
                ptr = ptr.add(put_varint_raw(ptr, count as u64));
                for &v in &vals[..count] {
                    ptr = ptr.add(put_varint_raw(ptr, v));
                }
                dst.set_len(start_len + exact);
            }
            return Ok(());
        }

        let payload_bytes: usize = items
            .iter()
            .map(|item| varint_len(to_u64(item)))
            .fold(0usize, usize::saturating_add);
        let cn = varint_len(count as u64);
        let sub_len = 1usize
            .checked_add(cn)
            .and_then(|n| n.checked_add(payload_bytes))
            .expect("capacity overflow");
        let lw = container_len_width(sub_len);
        let tw = varint_len(tag);
        let exact = tw
            .checked_add(lw)
            .and_then(|n| n.checked_add(sub_len))
            .expect("capacity overflow");
        dst.reserve(exact.checked_add(8).expect("capacity overflow"));
        let start_len = dst.len();
        let len_pos = start_len + tw;
        // SAFETY: `dst.reserve(exact + 8)` guarantees room for the header and expected payload;
        // each loop iteration ensures at least 9 bytes remain in `dst.capacity()` before calling
        // `put_varint_raw`, and `dst.set_len(written)` records the exact initialized byte count.
        unsafe {
            let mut ptr = dst.as_mut_ptr().add(start_len);
            ptr = ptr.add(put_varint_raw(ptr, tag));
            ptr = ptr.add(put_container_len_raw(ptr, sub_len));
            *ptr = elem_wt;
            ptr = ptr.add(1);
            ptr = ptr.add(put_varint_raw(ptr, count as u64));
            let mut written = ptr.offset_from(dst.as_ptr()) as usize;
            for item in items {
                let v = to_u64(item);
                if written + 9 > dst.capacity() {
                    dst.set_len(written);
                    dst.reserve(9);
                }
                let vn = put_varint_raw(dst.as_mut_ptr().add(written), v);
                written += vn;
            }
            dst.set_len(written);
        }
        let actual_sub_len = dst.len() - (len_pos + lw);
        if actual_sub_len != sub_len {
            if lw == 9 {
                backpatch_container_len_9b(dst, len_pos);
            } else if lw == 4 {
                backpatch_container_len_4b(dst, len_pos);
            } else if lw == 2 {
                backpatch_container_len(dst, len_pos);
            }
        }
        Ok(())
    }

    #[inline(always)]
    fn write_le_fixed_vec_field<T: Copy>(
        dst: &mut Vec<u8>,
        field_num: u32,
        elem_wt: u8,
        items: &[T],
        #[cfg(not(target_endian = "little"))] write_le: fn(*mut u8, T),
    ) -> Result<()> {
        let count = items.len();
        let elem_size = core::mem::size_of::<T>();
        let payload_bytes = count.checked_mul(elem_size).expect("capacity overflow");
        let cn = varint_len(count as u64);
        let sub_len = 1usize
            .checked_add(cn)
            .and_then(|n| n.checked_add(payload_bytes))
            .expect("capacity overflow");
        let tag = (u64::from(field_num) << 4) | u64::from(WIRE_ARRAY);
        let tw = varint_len(tag);
        let lw = container_len_width(sub_len);
        let exact = tw
            .checked_add(lw)
            .and_then(|n| n.checked_add(sub_len))
            .expect("capacity overflow");
        let need = exact.checked_add(8).expect("capacity overflow");
        let start_len = dst.len();
        if dst.capacity() - start_len < need {
            dst.reserve(need);
        }
        // SAFETY: At least `exact + 8` writable bytes exist at `start_len` (providing at least
        // 9 writable bytes at every `put_varint_raw` / `put_container_len_raw` call), `items` is
        // disjoint from `dst`, and exactly `exact` bytes are initialized before `set_len`.
        unsafe {
            let mut ptr = dst.as_mut_ptr().add(start_len);
            ptr = ptr.add(put_varint_raw(ptr, tag));
            ptr = ptr.add(put_container_len_raw(ptr, sub_len));
            *ptr = elem_wt;
            ptr = ptr.add(1);
            ptr = ptr.add(put_varint_raw(ptr, count as u64));
            if payload_bytes > 0 {
                #[cfg(target_endian = "little")]
                {
                    core::ptr::copy_nonoverlapping(items.as_ptr().cast::<u8>(), ptr, payload_bytes);
                }
                #[cfg(not(target_endian = "little"))]
                {
                    for &item in items {
                        write_le(ptr, item);
                        ptr = ptr.add(elem_size);
                    }
                }
            }
            dst.set_len(start_len + exact);
        }
        Ok(())
    }

    /// Encodes `Vec<f64>` as `WireArray(WireFloat64)` with exact length calculation and bulk copy.
    #[inline(always)]
    pub fn write_float64_vec_field(dst: &mut Vec<u8>, field_num: u32, items: &[f64]) -> Result<()> {
        write_le_fixed_vec_field(
            dst,
            field_num,
            WIRE_FLOAT64,
            items,
            #[cfg(not(target_endian = "little"))]
            |ptr, v| {
                // SAFETY: Caller guarantees 8 writable bytes at `ptr`.
                unsafe {
                    core::ptr::copy_nonoverlapping(v.to_bits().to_le_bytes().as_ptr(), ptr, 8);
                }
            },
        )
    }

    /// Encodes `Vec<f32>` as `WireArray(WireFloat32)` with exact length calculation and bulk copy.
    #[inline(always)]
    pub fn write_float32_vec_field(dst: &mut Vec<u8>, field_num: u32, items: &[f32]) -> Result<()> {
        write_le_fixed_vec_field(
            dst,
            field_num,
            WIRE_FLOAT32,
            items,
            #[cfg(not(target_endian = "little"))]
            |ptr, v| {
                // SAFETY: Caller guarantees 4 writable bytes at `ptr`.
                unsafe {
                    core::ptr::copy_nonoverlapping(v.to_bits().to_le_bytes().as_ptr(), ptr, 4);
                }
            },
        )
    }

    /// Encodes `Vec<u64>` as `WireArray(WireFixed64)` with exact length calculation and bulk copy.
    #[inline(always)]
    pub fn write_fixed64_vec_field(dst: &mut Vec<u8>, field_num: u32, items: &[u64]) -> Result<()> {
        write_le_fixed_vec_field(
            dst,
            field_num,
            WIRE_FIXED64,
            items,
            #[cfg(not(target_endian = "little"))]
            |ptr, v| {
                // SAFETY: Caller guarantees 8 writable bytes at `ptr`.
                unsafe {
                    core::ptr::copy_nonoverlapping(v.to_le_bytes().as_ptr(), ptr, 8);
                }
            },
        )
    }

    /// Encodes `Vec<i64>` as `WireArray(WireSfixed64)` with exact length calculation and bulk copy.
    #[inline(always)]
    pub fn write_sfixed64_vec_field(
        dst: &mut Vec<u8>,
        field_num: u32,
        items: &[i64],
    ) -> Result<()> {
        write_le_fixed_vec_field(
            dst,
            field_num,
            WIRE_SFIXED64,
            items,
            #[cfg(not(target_endian = "little"))]
            |ptr, v| {
                // SAFETY: Caller guarantees 8 writable bytes at `ptr`.
                unsafe {
                    core::ptr::copy_nonoverlapping(v.to_le_bytes().as_ptr(), ptr, 8);
                }
            },
        )
    }

    /// Encodes `Vec<u32>` as `WireArray(WireFixed32)` with exact length calculation and bulk copy.
    #[inline(always)]
    pub fn write_fixed32_vec_field(dst: &mut Vec<u8>, field_num: u32, items: &[u32]) -> Result<()> {
        write_le_fixed_vec_field(
            dst,
            field_num,
            WIRE_FIXED32,
            items,
            #[cfg(not(target_endian = "little"))]
            |ptr, v| {
                // SAFETY: Caller guarantees 4 writable bytes at `ptr`.
                unsafe {
                    core::ptr::copy_nonoverlapping(v.to_le_bytes().as_ptr(), ptr, 4);
                }
            },
        )
    }

    /// Encodes `Vec<i32>` as `WireArray(WireSfixed32)` with exact length calculation and bulk copy.
    #[inline(always)]
    pub fn write_sfixed32_vec_field(
        dst: &mut Vec<u8>,
        field_num: u32,
        items: &[i32],
    ) -> Result<()> {
        write_le_fixed_vec_field(
            dst,
            field_num,
            WIRE_SFIXED32,
            items,
            #[cfg(not(target_endian = "little"))]
            |ptr, v| {
                // SAFETY: Caller guarantees 4 writable bytes at `ptr`.
                unsafe {
                    core::ptr::copy_nonoverlapping(v.to_le_bytes().as_ptr(), ptr, 4);
                }
            },
        )
    }

    /// Encodes `Vec<bool>` as `WireArray(WireBoolFalse)` with exact length calculation and bulk copy.
    #[inline(always)]
    pub fn write_bool_vec_field(dst: &mut Vec<u8>, field_num: u32, items: &[bool]) -> Result<()> {
        write_le_fixed_vec_field(
            dst,
            field_num,
            WIRE_BOOL_FALSE,
            items,
            #[cfg(not(target_endian = "little"))]
            |ptr, v| {
                // SAFETY: Caller guarantees 1 writable byte at `ptr`.
                unsafe {
                    *ptr = u8::from(v);
                }
            },
        )
    }

    #[cold]
    #[inline(never)]
    unsafe fn grow_raw_cursor(
        dst: &mut Vec<u8>,
        ptr: &mut *mut u8,
        end: &mut *mut u8,
        needed: usize,
    ) {
        // SAFETY: Caller guarantees `*ptr` is within `dst`'s allocation and initialized up to `*ptr`.
        unsafe {
            let written = (*ptr).offset_from(dst.as_ptr()) as usize;
            dst.set_len(written);
            dst.reserve(needed);
            let base = dst.as_mut_ptr();
            *ptr = base.add(written);
            *end = base.add(dst.capacity());
        }
    }

    /// Encodes `Vec<String>` as `WireArray(WireString)` in a single-pass raw-pointer loop.
    #[inline(always)]
    pub fn write_string_vec_field(
        dst: &mut Vec<u8>,
        field_num: u32,
        items: &[String],
    ) -> Result<()> {
        let count = items.len();
        let len_pos = begin_tagged_array(dst, field_num, WIRE_STRING, count);
        let cur_len = dst.len();
        // SAFETY: `cur_len <= dst.capacity()` always holds.
        let (mut ptr, mut end) = unsafe {
            let base = dst.as_mut_ptr();
            (base.add(cur_len), base.add(dst.capacity()))
        };
        for s in items {
            let b = s.as_bytes();
            let n = b.len();
            let need = n.checked_add(9).expect("capacity overflow");
            if (end as usize).wrapping_sub(ptr as usize) < need {
                // SAFETY: Every byte up to `ptr` has been initialized within `dst`.
                unsafe {
                    grow_raw_cursor(dst, &mut ptr, &mut end, need);
                }
            }
            // SAFETY: At least `n + 9` writable bytes remain at `ptr`, and `b` is disjoint from `dst`.
            unsafe {
                if n <= 127 {
                    *ptr = ((n as u8) << 1) | 1;
                    ptr = ptr.add(1);
                } else {
                    ptr = ptr.add(put_varint_raw(ptr, n as u64));
                }
                copy_bytes_fast(b.as_ptr(), ptr, n);
                ptr = ptr.add(n);
            }
        }
        // SAFETY: Every byte up to `ptr` has been initialized, and `len_pos + 2 <= new_len`.
        unsafe {
            let new_len = ptr.offset_from(dst.as_ptr()) as usize;
            dst.set_len(new_len);
            backpatch_container_len_fast(dst, len_pos);
        }
        Ok(())
    }

    /// Encodes `Vec<Vec<u8>>` as `WireArray(WireBytes)` in a single-pass raw-pointer loop.
    #[inline(always)]
    pub fn write_bytes_vec_field(
        dst: &mut Vec<u8>,
        field_num: u32,
        items: &[Vec<u8>],
    ) -> Result<()> {
        let count = items.len();
        let len_pos = begin_tagged_array(dst, field_num, WIRE_BYTES, count);
        let cur_len = dst.len();
        // SAFETY: `cur_len <= dst.capacity()` always holds.
        let (mut ptr, mut end) = unsafe {
            let base = dst.as_mut_ptr();
            (base.add(cur_len), base.add(dst.capacity()))
        };
        for b in items {
            let n = b.len();
            let need = n.checked_add(9).expect("capacity overflow");
            if (end as usize).wrapping_sub(ptr as usize) < need {
                // SAFETY: Every byte up to `ptr` has been initialized within `dst`.
                unsafe {
                    grow_raw_cursor(dst, &mut ptr, &mut end, need);
                }
            }
            // SAFETY: At least `n + 9` writable bytes remain at `ptr`, and `b` is disjoint from `dst`.
            unsafe {
                if n <= 127 {
                    *ptr = ((n as u8) << 1) | 1;
                    ptr = ptr.add(1);
                } else {
                    ptr = ptr.add(put_varint_raw(ptr, n as u64));
                }
                copy_bytes_fast(b.as_ptr(), ptr, n);
                ptr = ptr.add(n);
            }
        }
        // SAFETY: Every byte up to `ptr` has been initialized, and `len_pos + 2 <= new_len`.
        unsafe {
            let new_len = ptr.offset_from(dst.as_ptr()) as usize;
            dst.set_len(new_len);
            backpatch_container_len_fast(dst, len_pos);
        }
        Ok(())
    }

    #[inline(always)]
    fn all_valid_bool_bytes(bytes: &[u8]) -> bool {
        let n = bytes.len();
        let ptr = bytes.as_ptr();
        let mut i = 0usize;
        while i + 8 <= n {
            // SAFETY: `i + 8 <= n`.
            let w = unsafe { core::ptr::read_unaligned(ptr.add(i).cast::<u64>()) };
            if (w & !0x0101_0101_0101_0101u64) != 0 {
                return false;
            }
            i += 8;
        }
        if i < n && n >= 8 {
            // SAFETY: `n >= 8`, so the trailing 8-byte window is in bounds.
            let w = unsafe { core::ptr::read_unaligned(ptr.add(n - 8).cast::<u64>()) };
            return (w & !0x0101_0101_0101_0101u64) == 0;
        }
        while i < n {
            // SAFETY: `i < n`.
            if unsafe { *ptr.add(i) } > 1 {
                return false;
            }
            i += 1;
        }
        true
    }

    #[inline(always)]
    fn read_le_fixed_vec_field<T: Copy>(
        items: &mut Vec<T>,
        data: &[u8],
        pos: usize,
        depth: usize,
        elem_wt: u8,
        reset: bool,
        #[cfg(not(target_endian = "little"))] read_le: fn(*const u8) -> T,
    ) -> Result<usize> {
        if depth + 1 > MAX_NESTING_DEPTH {
            return Err(Error::DepthLimitExceeded(depth + 1));
        }
        let (body, next_pos) = read_container_slice(data, pos, 2)?;
        if reset {
            items.clear();
        }
        let (count, p) = parse_array_header_typed(body, elem_wt)
            .ok_or_else(|| cold_parse_err("invalid WireArray header"))?;
        let nbytes = body.len() - p;
        super::charge_typed_alloc(nbytes)?;
        if count > 0 {
            let base = items.len();
            let total = base.saturating_add(count);
            if items.capacity() < total {
                items.reserve(grow_capacity(items.capacity(), total) - base);
            }
            #[cfg(target_endian = "little")]
            // SAFETY: `parse_array_header_typed` verified `nbytes == count * size_of::<T>()`,
            // `items` reserved space for `base + count` elements, `body` is disjoint from `items`,
            // and `T` is a plain little-endian numeric type.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    body.as_ptr().add(p),
                    items.as_mut_ptr().add(base).cast::<u8>(),
                    nbytes,
                );
                items.set_len(base + count);
            }
            #[cfg(not(target_endian = "little"))]
            // SAFETY: `parse_array_header_typed` verified `nbytes == count * size_of::<T>()` and
            // `items` reserved space for `base + count` elements.
            unsafe {
                let src = body.as_ptr().add(p);
                let dst = items.as_mut_ptr().add(base);
                let elem_size = core::mem::size_of::<T>();
                for i in 0..count {
                    dst.add(i).write(read_le(src.add(i * elem_size)));
                }
                items.set_len(base + count);
            }
        }
        Ok(next_pos)
    }

    /// Decodes `WireArray(WireFloat64)` directly into `Vec<f64>` using a single bulk copy.
    #[inline(always)]
    pub fn read_float64_vec_field(
        items: &mut Vec<f64>,
        data: &[u8],
        pos: usize,
        depth: usize,
        reset: bool,
    ) -> Result<usize> {
        read_le_fixed_vec_field(
            items,
            data,
            pos,
            depth,
            WIRE_FLOAT64,
            reset,
            #[cfg(not(target_endian = "little"))]
            |p| {
                // SAFETY: Caller guarantees 8 readable bytes at `p`.
                let raw = unsafe { core::ptr::read_unaligned(p.cast::<[u8; 8]>()) };
                f64::from_bits(u64::from_le_bytes(raw))
            },
        )
    }

    /// Decodes `WireArray(WireFloat32)` directly into `Vec<f32>` using a single bulk copy.
    #[inline(always)]
    pub fn read_float32_vec_field(
        items: &mut Vec<f32>,
        data: &[u8],
        pos: usize,
        depth: usize,
        reset: bool,
    ) -> Result<usize> {
        read_le_fixed_vec_field(
            items,
            data,
            pos,
            depth,
            WIRE_FLOAT32,
            reset,
            #[cfg(not(target_endian = "little"))]
            |p| {
                // SAFETY: Caller guarantees 4 readable bytes at `p`.
                let raw = unsafe { core::ptr::read_unaligned(p.cast::<[u8; 4]>()) };
                f32::from_bits(u32::from_le_bytes(raw))
            },
        )
    }

    /// Decodes `WireArray(WireFixed64)` directly into `Vec<u64>` using a single bulk copy.
    #[inline(always)]
    pub fn read_fixed64_vec_field(
        items: &mut Vec<u64>,
        data: &[u8],
        pos: usize,
        depth: usize,
        reset: bool,
    ) -> Result<usize> {
        read_le_fixed_vec_field(
            items,
            data,
            pos,
            depth,
            WIRE_FIXED64,
            reset,
            #[cfg(not(target_endian = "little"))]
            |p| {
                // SAFETY: Caller guarantees 8 readable bytes at `p`.
                let raw = unsafe { core::ptr::read_unaligned(p.cast::<[u8; 8]>()) };
                u64::from_le_bytes(raw)
            },
        )
    }

    /// Decodes `WireArray(WireSfixed64)` directly into `Vec<i64>` using a single bulk copy.
    #[inline(always)]
    pub fn read_sfixed64_vec_field(
        items: &mut Vec<i64>,
        data: &[u8],
        pos: usize,
        depth: usize,
        reset: bool,
    ) -> Result<usize> {
        read_le_fixed_vec_field(
            items,
            data,
            pos,
            depth,
            WIRE_SFIXED64,
            reset,
            #[cfg(not(target_endian = "little"))]
            |p| {
                // SAFETY: Caller guarantees 8 readable bytes at `p`.
                let raw = unsafe { core::ptr::read_unaligned(p.cast::<[u8; 8]>()) };
                i64::from_le_bytes(raw)
            },
        )
    }

    /// Decodes `WireArray(WireFixed32)` directly into `Vec<u32>` using a single bulk copy.
    #[inline(always)]
    pub fn read_fixed32_vec_field(
        items: &mut Vec<u32>,
        data: &[u8],
        pos: usize,
        depth: usize,
        reset: bool,
    ) -> Result<usize> {
        read_le_fixed_vec_field(
            items,
            data,
            pos,
            depth,
            WIRE_FIXED32,
            reset,
            #[cfg(not(target_endian = "little"))]
            |p| {
                // SAFETY: Caller guarantees 4 readable bytes at `p`.
                let raw = unsafe { core::ptr::read_unaligned(p.cast::<[u8; 4]>()) };
                u32::from_le_bytes(raw)
            },
        )
    }

    /// Decodes `WireArray(WireSfixed32)` directly into `Vec<i32>` using a single bulk copy.
    #[inline(always)]
    pub fn read_sfixed32_vec_field(
        items: &mut Vec<i32>,
        data: &[u8],
        pos: usize,
        depth: usize,
        reset: bool,
    ) -> Result<usize> {
        read_le_fixed_vec_field(
            items,
            data,
            pos,
            depth,
            WIRE_SFIXED32,
            reset,
            #[cfg(not(target_endian = "little"))]
            |p| {
                // SAFETY: Caller guarantees 4 readable bytes at `p`.
                let raw = unsafe { core::ptr::read_unaligned(p.cast::<[u8; 4]>()) };
                i32::from_le_bytes(raw)
            },
        )
    }

    /// Decodes `WireArray(WireBoolFalse)` into `Vec<bool>` after validating every byte is `0` or `1`.
    #[inline(always)]
    pub fn read_bool_vec_field(
        items: &mut Vec<bool>,
        data: &[u8],
        pos: usize,
        depth: usize,
        reset: bool,
    ) -> Result<usize> {
        if depth + 1 > MAX_NESTING_DEPTH {
            return Err(Error::DepthLimitExceeded(depth + 1));
        }
        let (body, next_pos) = read_container_slice(data, pos, 2)?;
        if reset {
            items.clear();
        }
        let (count, p) = parse_array_header_typed(body, WIRE_BOOL_FALSE)
            .ok_or_else(|| cold_parse_err("invalid WireArray(WireBool) header"))?;
        super::charge_typed_alloc(count)?;
        if count > 0 {
            let payload = &body[p..];
            if !all_valid_bool_bytes(payload) {
                return Err(cold_parse_err("invalid bool byte"));
            }
            let base = items.len();
            let total = base.saturating_add(count);
            if items.capacity() < total {
                items.reserve(grow_capacity(items.capacity(), total) - base);
            }
            // SAFETY: `parse_array_header_typed` verified `payload.len() == count`,
            // `all_valid_bool_bytes` verified every byte is `0u8` or `1u8` (valid Rust `bool`),
            // `items` reserved space for `base + count` elements, and `payload` is disjoint from `items`.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    payload.as_ptr(),
                    items.as_mut_ptr().add(base).cast::<u8>(),
                    count,
                );
                items.set_len(base + count);
            }
        }
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
        let count = items.len();
        let fixed_w = match elem_wt {
            WIRE_BOOL_FALSE => 1usize,
            WIRE_FIXED32 | WIRE_FLOAT32 | WIRE_SFIXED32 => 4,
            WIRE_FIXED64 | WIRE_FLOAT64 | WIRE_SFIXED64 => 8,
            _ => 0,
        };
        let min_body = if fixed_w > 0 {
            1usize
                .saturating_add(varint_len(count as u64))
                .saturating_add(count.saturating_mul(fixed_w))
        } else {
            1usize
                .saturating_add(varint_len(count as u64))
                .saturating_add(count)
        };
        if min_body > 16_383 {
            dst.reserve(min_body.saturating_add(24));
            let len_pos = begin_tagged_array_4b(dst, field_num, elem_wt, count);
            for item in items {
                write_elem(dst, item)?;
            }
            backpatch_container_len_4b(dst, len_pos);
        } else {
            if fixed_w > 0 && count > 0 {
                dst.reserve(min_body.saturating_add(16));
            }
            let len_pos = begin_tagged_array(dst, field_num, elem_wt, count);
            for item in items {
                write_elem(dst, item)?;
            }
            backpatch_container_len(dst, len_pos);
        }
        Ok(())
    }

    struct SetLenOnDrop<'a, T> {
        vec: &'a mut Vec<T>,
        len: usize,
    }

    impl<T> Drop for SetLenOnDrop<'_, T> {
        #[inline(always)]
        fn drop(&mut self) {
            // SAFETY: `self.len` elements have been initialized within `self.vec`'s capacity.
            unsafe {
                self.vec.set_len(self.len);
            }
        }
    }

    #[cold]
    #[inline(never)]
    fn read_scalar_vec_large<T, F>(
        items: &mut Vec<T>,
        body: &[u8],
        mut p: usize,
        count: usize,
        mut read_elem: F,
    ) -> Result<()>
    where
        F: FnMut(&[u8], usize) -> Result<(T, usize)>,
    {
        let base = items.len();
        let total = base.saturating_add(4096);
        if items.capacity() < total {
            items.reserve(grow_capacity(items.capacity(), total) - base);
        }
        for _ in 0..count {
            let (val, next_p) = read_elem(body, p)?;
            items.push(val);
            p = next_p;
        }
        if p != body.len() {
            return Err(cold_parse_err("WireArray trailing bytes"));
        }
        Ok(())
    }

    /// Decodes a `WireArray(WireUint)` directly into `Vec<u32>` with zero closure overhead.
    #[inline(always)]
    pub fn read_uint32_vec_field(
        items: &mut Vec<u32>,
        data: &[u8],
        pos: usize,
        depth: usize,
        reset: bool,
    ) -> Result<usize> {
        if depth + 1 > MAX_NESTING_DEPTH {
            return Err(Error::DepthLimitExceeded(depth + 1));
        }
        let (body, next_pos) = read_container_slice(data, pos, 2)?;
        if reset {
            items.clear();
        }
        let (count, mut p) = parse_array_header_typed(body, WIRE_UINT)
            .ok_or_else(|| cold_parse_err("invalid WireArray(WireUint) header"))?;
        super::charge_typed_alloc(count.saturating_mul(core::mem::size_of::<u32>()))?;
        if count > 4096 {
            read_scalar_vec_large(items, body, p, count, |b, off| {
                read_varint_at(b, off).map(|(v, np)| (v as u32, np))
            })?;
            return Ok(next_pos);
        }
        let base = items.len();
        let total = base.saturating_add(count);
        if items.capacity() < total {
            items.reserve(grow_capacity(items.capacity(), total) - base);
        }
        let ptr = items.as_mut_ptr();
        for i in 0..count {
            let Some((v, next_p)) = read_varint_at_opt(body, p) else {
                return Err(cold_parse_err("truncated or invalid varint"));
            };
            // SAFETY: `items` reserved space for `base + count` elements; `u32` is `Copy`.
            unsafe {
                ptr.add(base + i).write(v as u32);
            }
            p = next_p;
        }
        if p != body.len() {
            return Err(cold_parse_err("WireArray trailing bytes"));
        }
        // SAFETY: All `count` elements in `base..base + count` were initialized above.
        unsafe {
            items.set_len(base + count);
        }
        Ok(next_pos)
    }

    /// Decodes a `WireArray(WireUint)` directly into `Vec<u64>` with zero closure overhead.
    #[inline(always)]
    pub fn read_uint64_vec_field(
        items: &mut Vec<u64>,
        data: &[u8],
        pos: usize,
        depth: usize,
        reset: bool,
    ) -> Result<usize> {
        if depth + 1 > MAX_NESTING_DEPTH {
            return Err(Error::DepthLimitExceeded(depth + 1));
        }
        let (body, next_pos) = read_container_slice(data, pos, 2)?;
        if reset {
            items.clear();
        }
        let (count, mut p) = parse_array_header_typed(body, WIRE_UINT)
            .ok_or_else(|| cold_parse_err("invalid WireArray(WireUint) header"))?;
        super::charge_typed_alloc(count.saturating_mul(core::mem::size_of::<u64>()))?;
        if count > 4096 {
            read_scalar_vec_large(items, body, p, count, read_varint_at)?;
            return Ok(next_pos);
        }
        let base = items.len();
        let total = base.saturating_add(count);
        if items.capacity() < total {
            items.reserve(grow_capacity(items.capacity(), total) - base);
        }
        let ptr = items.as_mut_ptr();
        for i in 0..count {
            let Some((v, next_p)) = read_varint_at_opt(body, p) else {
                return Err(cold_parse_err("truncated or invalid varint"));
            };
            // SAFETY: `items` reserved space for `base + count` elements; `u64` is `Copy`.
            unsafe {
                ptr.add(base + i).write(v);
            }
            p = next_p;
        }
        if p != body.len() {
            return Err(cold_parse_err("WireArray trailing bytes"));
        }
        // SAFETY: All `count` elements in `base..base + count` were initialized above.
        unsafe {
            items.set_len(base + count);
        }
        Ok(next_pos)
    }

    /// Decodes a `WireArray(WireString)` directly into `Vec<String>` with zero closure overhead.
    #[inline(always)]
    pub fn read_string_vec_field(
        items: &mut Vec<String>,
        data: &[u8],
        pos: usize,
        depth: usize,
        reset: bool,
    ) -> Result<usize> {
        if depth + 1 > MAX_NESTING_DEPTH {
            return Err(Error::DepthLimitExceeded(depth + 1));
        }
        let (body, next_pos) = read_container_slice(data, pos, 2)?;
        if reset {
            items.clear();
        }
        let (count, mut p) = parse_array_header_typed(body, WIRE_STRING)
            .ok_or_else(|| cold_parse_err("invalid WireArray(WireString) header"))?;
        super::charge_typed_alloc(count.saturating_mul(core::mem::size_of::<String>()))?;
        if count > 4096 {
            read_scalar_vec_large(items, body, p, count, read_elem_string)?;
            return Ok(next_pos);
        }
        let base = items.len();
        let total = base.saturating_add(count);
        if items.capacity() < total {
            items.reserve(grow_capacity(items.capacity(), total) - base);
        }
        let mut guard = SetLenOnDrop {
            vec: items,
            len: base,
        };
        let ptr = guard.vec.as_mut_ptr();
        let body_len = body.len();
        let body_ptr = body.as_ptr();
        for _ in 0..count {
            let (raw, next_p) = if p < body_len {
                // SAFETY: `p < body_len`.
                let b0 = unsafe { *body_ptr.add(p) };
                if (b0 & 1) != 0 {
                    let slen = usize::from(b0 >> 1);
                    let start = p + 1;
                    if slen <= body_len - start {
                        // SAFETY: `start + slen <= body_len`.
                        (
                            unsafe { core::slice::from_raw_parts(body_ptr.add(start), slen) },
                            start + slen,
                        )
                    } else {
                        return Err(cold_parse_err("invalid container byteLen"));
                    }
                } else {
                    let Some(pair) = read_len_slice_opt(body, p, 0) else {
                        return Err(cold_parse_err("invalid container byteLen"));
                    };
                    pair
                }
            } else {
                return Err(cold_parse_err("invalid container byteLen"));
            };
            let s = bytes_to_owned_utf8(raw)?;
            // SAFETY: `items` reserved space for at least `base + count` elements.
            unsafe {
                ptr.add(guard.len).write(s);
            }
            guard.len += 1;
            p = next_p;
        }
        drop(guard);
        if p != body_len {
            return Err(cold_parse_err("WireArray trailing bytes"));
        }
        Ok(next_pos)
    }

    /// Decodes a `WireArray(WireBytes)` directly into `Vec<Vec<u8>>` with zero closure overhead.
    #[inline(always)]
    pub fn read_bytes_vec_field(
        items: &mut Vec<Vec<u8>>,
        data: &[u8],
        pos: usize,
        depth: usize,
        reset: bool,
    ) -> Result<usize> {
        if depth + 1 > MAX_NESTING_DEPTH {
            return Err(Error::DepthLimitExceeded(depth + 1));
        }
        let (body, next_pos) = read_container_slice(data, pos, 2)?;
        if reset {
            items.clear();
        }
        let (count, mut p) = parse_array_header_typed(body, WIRE_BYTES)
            .ok_or_else(|| cold_parse_err("invalid WireArray(WireBytes) header"))?;
        super::charge_typed_alloc(count.saturating_mul(core::mem::size_of::<Vec<u8>>()))?;
        if count > 4096 {
            read_scalar_vec_large(items, body, p, count, read_elem_bytes)?;
            return Ok(next_pos);
        }
        let base = items.len();
        let total = base.saturating_add(count);
        if items.capacity() < total {
            items.reserve(grow_capacity(items.capacity(), total) - base);
        }
        let mut guard = SetLenOnDrop {
            vec: items,
            len: base,
        };
        let ptr = guard.vec.as_mut_ptr();
        let body_len = body.len();
        let body_ptr = body.as_ptr();
        for _ in 0..count {
            let (raw, next_p) = if p < body_len {
                // SAFETY: `p < body_len`.
                let b0 = unsafe { *body_ptr.add(p) };
                if (b0 & 1) != 0 {
                    let blen = usize::from(b0 >> 1);
                    let start = p + 1;
                    if blen <= body_len - start {
                        // SAFETY: `start + blen <= body_len`.
                        (
                            unsafe { core::slice::from_raw_parts(body_ptr.add(start), blen) },
                            start + blen,
                        )
                    } else {
                        return Err(cold_parse_err("invalid container byteLen"));
                    }
                } else {
                    let Some(pair) = read_len_slice_opt(body, p, 0) else {
                        return Err(cold_parse_err("invalid container byteLen"));
                    };
                    pair
                }
            } else {
                return Err(cold_parse_err("invalid container byteLen"));
            };
            // SAFETY: `items` reserved space for at least `base + count` elements.
            unsafe {
                ptr.add(guard.len).write(bytes_to_owned_vec(raw));
            }
            guard.len += 1;
            p = next_p;
        }
        drop(guard);
        if p != body_len {
            return Err(cold_parse_err("WireArray trailing bytes"));
        }
        Ok(next_pos)
    }

    /// Decodes a `WireArray` of scalar elements using `read_elem`.
    #[inline(always)]
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
        let (body, next_pos) = read_container_slice(data, pos, 2)?;
        if reset {
            items.clear();
        }
        let (count, mut p) = parse_array_header_typed(body, exp_elem_wt)
            .ok_or_else(|| cold_parse_err("invalid WireArray header"))?;
        super::charge_typed_alloc(count.saturating_mul(core::mem::size_of::<T>()))?;
        if count > 4096 {
            read_scalar_vec_large(items, body, p, count, read_elem)?;
            return Ok(next_pos);
        }
        let base = items.len();
        let total = base.saturating_add(count);
        if items.capacity() < total {
            items.reserve(grow_capacity(items.capacity(), total) - base);
        }
        let mut guard = SetLenOnDrop {
            vec: items,
            len: base,
        };
        let ptr = guard.vec.as_mut_ptr();
        for _ in 0..count {
            let (val, next_p) = read_elem(body, p)?;
            // SAFETY: `items` reserved space for at least `base + count` elements.
            unsafe {
                ptr.add(guard.len).write(val);
            }
            guard.len += 1;
            p = next_p;
        }
        drop(guard);
        if p != body.len() {
            return Err(cold_parse_err("WireArray trailing bytes"));
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
        let count = items.len();
        if dst.capacity() > 16_383 && (count >= 32 || (M::HAS_NESTED_CONTAINERS && count > 0)) {
            let mut elems_min = 0usize;
            for m in items {
                let em = m.min_wire_size();
                elems_min = elems_min.saturating_add(container_len_width(em).saturating_add(em));
                if elems_min > 16_383 {
                    break;
                }
            }
            let min_body = 1usize
                .saturating_add(varint_len(count as u64))
                .saturating_add(elems_min);
            if min_body > 16_383 {
                dst.reserve(min_body.saturating_add(64));
                let len_pos = begin_tagged_array_4b(dst, field_num, WIRE_SUB_MSG, count);
                for item in items {
                    write_sub_msg_elem(dst, item, deterministic)?;
                }
                backpatch_container_len_4b(dst, len_pos);
                return Ok(());
            }
        }
        let len_pos = begin_tagged_array(dst, field_num, WIRE_SUB_MSG, count);
        for item in items {
            let elem_pos = dst.len();
            if dst.capacity() - elem_pos < 2 {
                dst.reserve(2);
            }
            // SAFETY: At least 2 writable bytes exist at `elem_pos`.
            unsafe {
                let ptr = dst.as_mut_ptr().add(elem_pos);
                *ptr = 0;
                *ptr.add(1) = 0;
                dst.set_len(elem_pos + 2);
            }
            item.encode_omnibuf_append(dst, deterministic)?;
            // SAFETY: We just wrote the 2-byte length slot at `elem_pos`.
            unsafe { backpatch_container_len_fast(dst, elem_pos) };
        }
        // SAFETY: `begin_tagged_array` wrote the 2-byte length slot at `len_pos`.
        unsafe { backpatch_container_len_fast(dst, len_pos) };
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
        let count = items.len();
        if dst.capacity() > 16_383 && (count >= 32 || (M::HAS_NESTED_CONTAINERS && count > 0)) {
            let mut elems_min = 0usize;
            for m in items {
                let em = m.min_wire_size();
                elems_min = elems_min.saturating_add(container_len_width(em).saturating_add(em));
                if elems_min > 16_383 {
                    break;
                }
            }
            let min_body = 1usize
                .saturating_add(varint_len(count as u64))
                .saturating_add(elems_min);
            if min_body > 16_383 {
                dst.reserve(min_body.saturating_add(24));
                let len_pos = begin_tagged_array_4b(dst, field_num, WIRE_SUB_MSG, count);
                for item in items {
                    write_sub_msg_elem(dst, item.as_ref(), deterministic)?;
                }
                backpatch_container_len_4b(dst, len_pos);
                return Ok(());
            }
        }
        let len_pos = begin_tagged_array(dst, field_num, WIRE_SUB_MSG, count);
        for item in items {
            let elem_pos = dst.len();
            if dst.capacity() - elem_pos < 2 {
                dst.reserve(2);
            }
            // SAFETY: At least 2 writable bytes exist at `elem_pos`.
            unsafe {
                let ptr = dst.as_mut_ptr().add(elem_pos);
                *ptr = 0;
                *ptr.add(1) = 0;
                dst.set_len(elem_pos + 2);
            }
            item.encode_omnibuf_append(dst, deterministic)?;
            // SAFETY: We just wrote the 2-byte length slot at `elem_pos`.
            unsafe { backpatch_container_len_fast(dst, elem_pos) };
        }
        // SAFETY: `begin_tagged_array` wrote the 2-byte length slot at `len_pos`.
        unsafe { backpatch_container_len_fast(dst, len_pos) };
        Ok(())
    }

    #[cold]
    #[inline(never)]
    fn read_sub_msg_vec_large<M: Message>(
        items: &mut Vec<M>,
        body: &[u8],
        mut p: usize,
        count: usize,
        depth: usize,
    ) -> Result<()> {
        let base = items.len();
        let total = base.saturating_add(4096);
        if items.capacity() < total {
            items.reserve(grow_capacity(items.capacity(), total) - base);
        }
        for _ in 0..count {
            let (elem_bytes, next_p) = read_container_slice(body, p, 0)?;
            let mut elem = M::default();
            elem.decode_omnibuf_at_depth(elem_bytes, depth + 2, true)?;
            items.push(elem);
            p = next_p;
        }
        if p != body.len() {
            return Err(cold_parse_err("WireArray(WireSubMsg) trailing bytes"));
        }
        Ok(())
    }

    /// Decodes `WireArray(WireSubMsg)` into `Vec<M>`.
    #[inline(always)]
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
        let (body, next_pos) = read_container_slice(data, pos, 2)?;
        if reset {
            items.clear();
        }
        let (count, mut p) = parse_array_header_typed(body, WIRE_SUB_MSG)
            .ok_or_else(|| cold_parse_err("invalid WireArray(WireSubMsg) header"))?;
        if count == 0 {
            if p != body.len() {
                return Err(cold_parse_err("WireArray(WireSubMsg) trailing bytes"));
            }
            return Ok(next_pos);
        }
        super::charge_typed_alloc(count.saturating_mul(core::mem::size_of::<M>()))?;
        if count > 4096 {
            read_sub_msg_vec_large(items, body, p, count, depth)?;
            return Ok(next_pos);
        }
        let base = items.len();
        let total = base.saturating_add(count);
        if items.capacity() < total {
            items.reserve(grow_capacity(items.capacity(), total) - base);
        }
        let mut guard = SetLenOnDrop {
            vec: items,
            len: base,
        };
        let ptr = guard.vec.as_mut_ptr();
        for _ in 0..count {
            let Some((elem_bytes, next_p)) = read_container_slice_opt(body, p, 0) else {
                return Err(cold_parse_err("invalid container byteLen"));
            };
            let mut elem = M::default();
            elem.decode_omnibuf_at_depth(elem_bytes, depth + 2, true)?;
            // SAFETY: `items` reserved space for at least `base + count` elements.
            unsafe {
                ptr.add(guard.len).write(elem);
            }
            guard.len += 1;
            p = next_p;
        }
        drop(guard);
        if p != body.len() {
            return Err(cold_parse_err("WireArray(WireSubMsg) trailing bytes"));
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
        let (body, next_pos) = read_container_slice(data, pos, 2)?;
        if reset {
            items.clear();
        }
        let (elem_wt, count, mut p) =
            parse_array_header(body).ok_or_else(|| cold_parse_err("invalid WireArray header"))?;
        if elem_wt != WIRE_SUB_MSG {
            return Err(cold_parse_err("expected WireArray(WireSubMsg)"));
        }
        super::charge_typed_alloc(count.saturating_mul(
            core::mem::size_of::<Box<M>>().saturating_add(core::mem::size_of::<M>()),
        ))?;
        let base = items.len();
        let cap_add = count.min(4096);
        let total = base.saturating_add(cap_add);
        if items.capacity() < total {
            items.reserve(grow_capacity(items.capacity(), total) - base);
        }
        for _ in 0..count {
            let (elem_bytes, next_p) = read_container_slice(body, p, 0)?;
            let mut elem = Box::new(M::default());
            elem.decode_omnibuf_at_depth(elem_bytes, depth + 2, true)?;
            items.push(elem);
            p = next_p;
        }
        if p != body.len() {
            return Err(cold_parse_err("WireArray(WireSubMsg) trailing bytes"));
        }
        Ok(next_pos)
    }

    #[inline]
    fn write_sub_msg_elem_with_min<M: Message>(
        dst: &mut Vec<u8>,
        msg: &M,
        min_sub: usize,
        deterministic: bool,
    ) -> Result<()> {
        if min_sub > 16_383 {
            dst.reserve(min_sub.saturating_add(8));
            let elem_pos = dst.len();
            dst.extend_from_slice(&[0, 0, 0, 0]);
            msg.encode_omnibuf_append(dst, deterministic)?;
            backpatch_container_len_4b(dst, elem_pos);
        } else {
            let elem_pos = dst.len();
            if dst.capacity() - elem_pos < 2 {
                dst.reserve(2);
            }
            // SAFETY: At least 2 writable bytes exist at `elem_pos`.
            unsafe {
                let ptr = dst.as_mut_ptr().add(elem_pos);
                *ptr = 0;
                *ptr.add(1) = 0;
                dst.set_len(elem_pos + 2);
            }
            msg.encode_omnibuf_append(dst, deterministic)?;
            // SAFETY: We just wrote the 2-byte length slot at `elem_pos`.
            unsafe { backpatch_container_len_fast(dst, elem_pos) };
        }
        Ok(())
    }

    /// Encodes an untagged `WireSubMsg` element inside a `WireArray` or `WireMap`.
    #[inline]
    pub fn write_sub_msg_elem<M: Message>(
        dst: &mut Vec<u8>,
        msg: &M,
        deterministic: bool,
    ) -> Result<()> {
        let min_sub = if M::HAS_NESTED_CONTAINERS && dst.capacity() > 16_383 {
            msg.min_wire_size()
        } else {
            0
        };
        write_sub_msg_elem_with_min(dst, msg, min_sub, deterministic)
    }

    /// Decodes an untagged `WireSubMsg` element inside a `WireArray` or `WireMap`.
    #[inline]
    pub fn read_sub_msg_elem<M: Message>(
        body: &[u8],
        p: usize,
        depth: usize,
    ) -> Result<(M, usize)> {
        let (elem_bytes, next_p) = read_container_slice(body, p, 0)?;
        let mut elem = M::default();
        elem.decode_omnibuf_at_depth(elem_bytes, depth + 1, true)?;
        Ok((elem, next_p))
    }

    /// Decodes an untagged `WireSubMsg` element into `Box<M>`.
    #[inline]
    pub fn read_box_sub_msg_elem<M: Message>(
        body: &[u8],
        p: usize,
        depth: usize,
    ) -> Result<(Box<M>, usize)> {
        let (elem_bytes, next_p) = read_container_slice(body, p, 0)?;
        super::charge_typed_alloc(core::mem::size_of::<M>())?;
        let mut elem = Box::new(M::default());
        elem.decode_omnibuf_at_depth(elem_bytes, depth + 1, true)?;
        Ok((elem, next_p))
    }

    /// Encodes a tagged `WireArray` field whose elements may themselves be containers.
    #[inline]
    pub fn write_vec_field<T, F>(
        dst: &mut Vec<u8>,
        field_num: u32,
        elem_wt: u8,
        items: &[T],
        deterministic: bool,
        mut write_elem: F,
    ) -> Result<()>
    where
        F: FnMut(&mut Vec<u8>, &T, bool) -> Result<()>,
    {
        let count = items.len();
        let min_body = 1usize
            .saturating_add(varint_len(count as u64))
            .saturating_add(count.saturating_mul(2));
        if min_body > 16_383 {
            let len_pos = begin_tagged_array_4b(dst, field_num, elem_wt, count);
            for item in items {
                write_elem(dst, item, deterministic)?;
            }
            backpatch_container_len_4b(dst, len_pos);
        } else {
            let len_pos = begin_tagged_array(dst, field_num, elem_wt, count);
            for item in items {
                write_elem(dst, item, deterministic)?;
            }
            backpatch_container_len(dst, len_pos);
        }
        Ok(())
    }

    /// Decodes a tagged `WireArray` field whose elements may themselves be containers.
    pub fn read_vec_field<T, F>(
        items: &mut Vec<T>,
        data: &[u8],
        pos: usize,
        depth: usize,
        exp_elem_wt: u8,
        reset: bool,
        mut read_elem: F,
    ) -> Result<usize>
    where
        F: FnMut(&[u8], usize, usize) -> Result<(T, usize)>,
    {
        if depth + 1 > MAX_NESTING_DEPTH {
            return Err(Error::DepthLimitExceeded(depth + 1));
        }
        let (body, next_pos) = read_container_slice(data, pos, 2)?;
        if reset {
            items.clear();
        }
        let (elem_wt, count, mut p) =
            parse_array_header(body).ok_or_else(|| cold_parse_err("invalid WireArray header"))?;
        if elem_wt != exp_elem_wt {
            return Err(cold_parse_err("WireArray element wire type mismatch"));
        }
        super::charge_typed_alloc(count.saturating_mul(core::mem::size_of::<T>()))?;
        let base = items.len();
        let cap_add = count.min(4096);
        let total = base.saturating_add(cap_add);
        if items.capacity() < total {
            items.reserve(grow_capacity(items.capacity(), total) - base);
        }
        for _ in 0..count {
            let (val, next_p) = read_elem(body, p, depth + 1)?;
            items.push(val);
            p = next_p;
        }
        if p != body.len() {
            return Err(cold_parse_err("WireArray trailing bytes"));
        }
        Ok(next_pos)
    }

    /// Encodes an untagged `WireArray` container inside a parent `WireArray` or `WireMap`.
    pub fn write_vec_elem<T, F>(
        dst: &mut Vec<u8>,
        elem_wt: u8,
        items: &[T],
        deterministic: bool,
        mut write_elem: F,
    ) -> Result<()>
    where
        F: FnMut(&mut Vec<u8>, &T, bool) -> Result<()>,
    {
        let len_pos = dst.len();
        dst.extend_from_slice(&[0, 0, elem_wt]);
        append_varint(dst, items.len() as u64);
        for item in items {
            write_elem(dst, item, deterministic)?;
        }
        backpatch_container_len(dst, len_pos);
        Ok(())
    }

    /// Decodes an untagged `WireArray` container inside a parent `WireArray` or `WireMap`.
    pub fn read_vec_elem<T, F>(
        data: &[u8],
        pos: usize,
        depth: usize,
        exp_elem_wt: u8,
        mut read_elem: F,
    ) -> Result<(Vec<T>, usize)>
    where
        F: FnMut(&[u8], usize, usize) -> Result<(T, usize)>,
    {
        if depth + 1 > MAX_NESTING_DEPTH {
            return Err(Error::DepthLimitExceeded(depth + 1));
        }
        let (body, next_pos) = read_container_slice(data, pos, 2)?;
        let (elem_wt, count, mut p) =
            parse_array_header(body).ok_or_else(|| cold_parse_err("invalid WireArray header"))?;
        if elem_wt != exp_elem_wt {
            return Err(cold_parse_err("WireArray element wire type mismatch"));
        }
        super::charge_typed_alloc(count.saturating_mul(core::mem::size_of::<T>()))?;
        let mut items = Vec::with_capacity(count.min(4096));
        for _ in 0..count {
            let (val, next_p) = read_elem(body, p, depth + 1)?;
            items.push(val);
            p = next_p;
        }
        if p != body.len() {
            return Err(cold_parse_err("WireArray trailing bytes"));
        }
        Ok((items, next_pos))
    }

    // ========================================================================
    // Scalar Element Payload Helpers (Inside WireArray & WireMap)
    // ========================================================================

    #[inline(always)]
    pub fn read_elem_uint(body: &[u8], p: usize) -> Result<(u64, usize)> {
        read_varint_at(body, p)
    }

    #[inline(always)]
    pub fn read_elem_sint(body: &[u8], p: usize) -> Result<(i64, usize)> {
        let (v, next_p) = read_varint_at(body, p)?;
        Ok((decode_zigzag(v), next_p))
    }

    #[inline(always)]
    pub fn read_elem_bool(body: &[u8], p: usize) -> Result<(bool, usize)> {
        let b = *body
            .get(p)
            .ok_or_else(|| cold_parse_err("truncated bool element"))?;
        match b {
            0 => Ok((false, p + 1)),
            1 => Ok((true, p + 1)),
            _ => Err(cold_parse_err("invalid bool byte")),
        }
    }

    #[inline(always)]
    pub fn read_elem_fixed32(body: &[u8], p: usize) -> Result<(u32, usize)> {
        if body.len().saturating_sub(p) < 4 {
            return Err(cold_parse_err("truncated fixed32 element"));
        }
        // SAFETY: `body.len() - p >= 4`, so 4 bytes at `p` are in bounds.
        let v = unsafe { core::ptr::read_unaligned(body.as_ptr().add(p).cast::<u32>()) }.to_le();
        Ok((v, p + 4))
    }

    #[inline(always)]
    pub fn read_elem_fixed64(body: &[u8], p: usize) -> Result<(u64, usize)> {
        if body.len().saturating_sub(p) < 8 {
            return Err(cold_parse_err("truncated fixed64 element"));
        }
        // SAFETY: `body.len() - p >= 8`, so 8 bytes at `p` are in bounds.
        let v = unsafe { core::ptr::read_unaligned(body.as_ptr().add(p).cast::<u64>()) }.to_le();
        Ok((v, p + 8))
    }

    #[inline(always)]
    pub fn read_elem_sfixed32(body: &[u8], p: usize) -> Result<(i32, usize)> {
        let (v, next_p) = read_elem_fixed32(body, p)?;
        Ok((v as i32, next_p))
    }

    #[inline(always)]
    pub fn read_elem_sfixed64(body: &[u8], p: usize) -> Result<(i64, usize)> {
        let (v, next_p) = read_elem_fixed64(body, p)?;
        Ok((v as i64, next_p))
    }

    #[inline(always)]
    pub fn read_elem_float32(body: &[u8], p: usize) -> Result<(f32, usize)> {
        let (v, next_p) = read_elem_fixed32(body, p)?;
        Ok((f32::from_bits(v), next_p))
    }

    #[inline(always)]
    pub fn read_elem_float64(body: &[u8], p: usize) -> Result<(f64, usize)> {
        let (v, next_p) = read_elem_fixed64(body, p)?;
        Ok((f64::from_bits(v), next_p))
    }

    #[inline(always)]
    pub fn read_elem_string(body: &[u8], p: usize) -> Result<(String, usize)> {
        let (raw, next_p) = read_len_slice(body, p, 0)?;
        Ok((bytes_to_owned_utf8(raw)?, next_p))
    }

    #[inline(always)]
    pub fn read_elem_bytes(body: &[u8], p: usize) -> Result<(Vec<u8>, usize)> {
        let (b, next_p) = read_len_slice(body, p, 0)?;
        Ok((bytes_to_owned_vec(b), next_p))
    }

    #[inline(always)]
    pub fn read_elem_str_borrowed(body: &[u8], p: usize) -> Result<(&str, usize)> {
        read_str_slice(body, p)
    }

    #[inline(always)]
    pub fn read_elem_bytes_borrowed(body: &[u8], p: usize) -> Result<(&[u8], usize)> {
        read_len_slice(body, p, 0)
    }

    #[inline]
    pub fn read_opt_sub_msg_borrowed_field<'de, M: DecodeBorrowed<'de>>(
        slot: &mut Option<M>,
        data: &'de [u8],
        pos: usize,
        depth: usize,
        merge: bool,
    ) -> Result<usize> {
        let (sub_bytes, next_pos) = read_container_slice(data, pos, 0)?;
        match slot {
            Some(msg) => msg.decode_omnibuf_borrowed_at_depth(sub_bytes, depth + 1, merge)?,
            None => {
                let mut msg = M::default();
                msg.decode_omnibuf_borrowed_at_depth(sub_bytes, depth + 1, true)?;
                *slot = Some(msg);
            }
        }
        Ok(next_pos)
    }

    #[inline]
    pub fn read_opt_box_sub_msg_borrowed_field<'de, M: DecodeBorrowed<'de>>(
        slot: &mut Option<Box<M>>,
        data: &'de [u8],
        pos: usize,
        depth: usize,
        merge: bool,
    ) -> Result<usize> {
        let (sub_bytes, next_pos) = read_container_slice(data, pos, 0)?;
        match slot {
            Some(msg) => msg.decode_omnibuf_borrowed_at_depth(sub_bytes, depth + 1, merge)?,
            None => {
                super::charge_typed_alloc(core::mem::size_of::<M>())?;
                let mut msg = Box::new(M::default());
                msg.decode_omnibuf_borrowed_at_depth(sub_bytes, depth + 1, true)?;
                *slot = Some(msg);
            }
        }
        Ok(next_pos)
    }

    /// Allocates and decodes a borrowed `Box<M>` from a `WireSubMsg` body, charging `size_of::<M>()`
    /// against the active `DecodeOptions::max_alloc_bytes` budget.
    #[inline]
    pub fn read_box_sub_msg_borrowed_value<'de, M: DecodeBorrowed<'de>>(
        sub_bytes: &'de [u8],
        depth: usize,
    ) -> Result<Box<M>> {
        super::charge_typed_alloc(core::mem::size_of::<M>())?;
        let mut msg = Box::new(M::default());
        msg.decode_omnibuf_borrowed_at_depth(sub_bytes, depth, true)?;
        Ok(msg)
    }

    #[inline]
    pub fn read_scalar_vec_borrowed_field<'de, T, F>(
        items: &mut Vec<T>,
        data: &'de [u8],
        pos: usize,
        depth: usize,
        exp_elem_wt: u8,
        reset: bool,
        mut read_elem: F,
    ) -> Result<usize>
    where
        F: FnMut(&'de [u8], usize) -> Result<(T, usize)>,
    {
        if depth + 1 > MAX_NESTING_DEPTH {
            return Err(Error::DepthLimitExceeded(depth + 1));
        }
        let (body, next_pos) = read_container_slice(data, pos, 2)?;
        if reset {
            items.clear();
        }
        let (elem_wt, count, mut p) =
            parse_array_header(body).ok_or_else(|| cold_parse_err("invalid WireArray header"))?;
        if elem_wt != exp_elem_wt {
            return Err(cold_parse_err("WireArray element wire type mismatch"));
        }
        super::charge_typed_alloc(count.saturating_mul(core::mem::size_of::<T>()))?;
        let base = items.len();
        let cap_add = count.min(4096);
        let total = base.saturating_add(cap_add);
        if items.capacity() < total {
            items.reserve(grow_capacity(items.capacity(), total) - base);
        }
        for _ in 0..count {
            let (val, next_p) = read_elem(body, p)?;
            items.push(val);
            p = next_p;
        }
        if p != body.len() {
            return Err(cold_parse_err("WireArray trailing bytes"));
        }
        Ok(next_pos)
    }

    #[inline]
    pub fn read_sub_msg_borrowed_vec_field<'de, M: DecodeBorrowed<'de>>(
        items: &mut Vec<M>,
        data: &'de [u8],
        pos: usize,
        depth: usize,
        reset: bool,
    ) -> Result<usize> {
        if depth + 1 > MAX_NESTING_DEPTH {
            return Err(Error::DepthLimitExceeded(depth + 1));
        }
        let (body, next_pos) = read_container_slice(data, pos, 2)?;
        if reset {
            items.clear();
        }
        let (elem_wt, count, mut p) =
            parse_array_header(body).ok_or_else(|| cold_parse_err("invalid WireArray header"))?;
        if elem_wt != WIRE_SUB_MSG {
            return Err(cold_parse_err("expected WireArray(WireSubMsg)"));
        }
        super::charge_typed_alloc(count.saturating_mul(core::mem::size_of::<M>()))?;
        let base = items.len();
        let cap_add = count.min(4096);
        let total = base.saturating_add(cap_add);
        if items.capacity() < total {
            items.reserve(grow_capacity(items.capacity(), total) - base);
        }
        for _ in 0..count {
            let (elem_bytes, next_p) = read_container_slice(body, p, 0)?;
            let mut elem = M::default();
            elem.decode_omnibuf_borrowed_at_depth(elem_bytes, depth + 2, true)?;
            items.push(elem);
            p = next_p;
        }
        if p != body.len() {
            return Err(cold_parse_err("WireArray(WireSubMsg) trailing bytes"));
        }
        Ok(next_pos)
    }

    /// Key and value wire types for a `WireMap` container.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct MapWireTypes {
        /// Wire type of each map key.
        pub key: u8,
        /// Wire type of each map value.
        pub val: u8,
    }

    impl MapWireTypes {
        /// Creates a new `(key, val)` wire-type pair.
        #[inline]
        pub const fn new(key: u8, val: u8) -> Self {
            Self { key, val }
        }
    }

    /// Cursor and validation context for decoding a `WireMap` field.
    #[derive(Clone, Copy, Debug)]
    pub struct MapReadCtx<'a> {
        /// Full wire buffer being decoded.
        pub data: &'a [u8],
        /// Byte offset of the `WireMap` length prefix within `data`.
        pub pos: usize,
        /// Current container nesting depth.
        pub depth: usize,
        /// Expected key and value wire types.
        pub wire_types: MapWireTypes,
        /// Whether to clear the target map before inserting decoded entries.
        pub reset: bool,
    }

    pub fn read_hash_map_borrowed_field<'de, K, V, S, FK, FV>(
        map: &mut HashMap<K, V, S>,
        ctx: MapReadCtx<'de>,
        mut read_key: FK,
        mut read_val: FV,
    ) -> Result<usize>
    where
        K: Eq + Hash,
        S: Default + std::hash::BuildHasher,
        FK: FnMut(&'de [u8], usize) -> Result<(K, usize)>,
        FV: FnMut(&'de [u8], usize, usize) -> Result<(V, usize)>,
    {
        if ctx.depth + 1 > MAX_NESTING_DEPTH {
            return Err(Error::DepthLimitExceeded(ctx.depth + 1));
        }
        let (body, next_pos) = read_container_slice(ctx.data, ctx.pos, 3)?;
        let (key_wt, val_wt, count, mut p) =
            parse_map_header(body).ok_or_else(|| Error::parse("invalid WireMap header"))?;
        if key_wt != ctx.wire_types.key || val_wt != ctx.wire_types.val {
            return Err(Error::parse(format!(
                "WireMap header mismatch: expected ({}, {}), got ({key_wt}, {val_wt})",
                ctx.wire_types.key, ctx.wire_types.val
            )));
        }
        super::charge_typed_alloc(
            count.saturating_mul(core::mem::size_of::<(K, V)>().saturating_add(16)),
        )?;
        if ctx.reset {
            map.clear();
        }
        map.reserve(count.min(4096));
        for _ in 0..count {
            let (k, after_k) = read_key(body, p)?;
            let (v, after_v) = read_val(body, after_k, ctx.depth + 1)?;
            map.insert(k, v);
            p = after_v;
        }
        if p != body.len() {
            return Err(Error::parse("WireMap trailing bytes"));
        }
        Ok(next_pos)
    }

    // ========================================================================
    // Generic WireMap Encoding & Decoding (HashMap & BTreeMap)
    // ========================================================================

    /// Encodes a `HashMap<K, V>` as a `WireMap` field, sorting keys via `Ord` when `deterministic` is `true`.
    pub fn write_hash_map_field<K, V, S, FK, FV>(
        dst: &mut Vec<u8>,
        field_num: u32,
        wire_types: MapWireTypes,
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
        let count = map.len();
        let min_body = 2usize
            .saturating_add(varint_len(count as u64))
            .saturating_add(count.saturating_mul(2));
        append_tag(dst, field_num, WIRE_MAP);
        let len_pos = dst.len();
        let use_4b = min_body > 16_383;
        if use_4b {
            dst.reserve(min_body.saturating_add(24));
            dst.extend_from_slice(&[0, 0, 0, 0, wire_types.key, wire_types.val]);
        } else {
            dst.extend_from_slice(&[0, 0, wire_types.key, wire_types.val]);
        }
        append_varint(dst, count as u64);
        if deterministic && count > 1 {
            let mut entries: Vec<(&K, &V)> = map.iter().collect();
            entries.sort_unstable_by_key(|(ka, _)| *ka);
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
        if use_4b {
            backpatch_container_len_4b(dst, len_pos);
        } else {
            backpatch_container_len(dst, len_pos);
        }
        Ok(())
    }

    /// Encodes a `BTreeMap<K, V>` as a `WireMap` field (keys are already in ascending `Ord` order).
    pub fn write_btree_map_field<K, V, FK, FV>(
        dst: &mut Vec<u8>,
        field_num: u32,
        wire_types: MapWireTypes,
        map: &BTreeMap<K, V>,
        deterministic: bool,
        mut write_key: FK,
        mut write_val: FV,
    ) -> Result<()>
    where
        FK: FnMut(&mut Vec<u8>, &K) -> Result<()>,
        FV: FnMut(&mut Vec<u8>, &V, bool) -> Result<()>,
    {
        let count = map.len();
        let min_body = 2usize
            .saturating_add(varint_len(count as u64))
            .saturating_add(count.saturating_mul(2));
        append_tag(dst, field_num, WIRE_MAP);
        let len_pos = dst.len();
        let use_4b = min_body > 16_383;
        if use_4b {
            dst.reserve(min_body.saturating_add(24));
            dst.extend_from_slice(&[0, 0, 0, 0, wire_types.key, wire_types.val]);
        } else {
            dst.extend_from_slice(&[0, 0, wire_types.key, wire_types.val]);
        }
        append_varint(dst, count as u64);
        for (k, v) in map {
            write_key(dst, k)?;
            write_val(dst, v, deterministic)?;
        }
        if use_4b {
            backpatch_container_len_4b(dst, len_pos);
        } else {
            backpatch_container_len(dst, len_pos);
        }
        Ok(())
    }

    /// Decodes a `WireMap` field into a `HashMap<K, V>`.
    pub fn read_hash_map_field<K, V, S, FK, FV>(
        map: &mut HashMap<K, V, S>,
        ctx: MapReadCtx<'_>,
        mut read_key: FK,
        mut read_val: FV,
    ) -> Result<usize>
    where
        K: Eq + Hash,
        S: Default + std::hash::BuildHasher,
        FK: FnMut(&[u8], usize) -> Result<(K, usize)>,
        FV: FnMut(&[u8], usize, usize) -> Result<(V, usize)>,
    {
        if ctx.depth + 1 > MAX_NESTING_DEPTH {
            return Err(Error::DepthLimitExceeded(ctx.depth + 1));
        }
        let (body, next_pos) = read_container_slice(ctx.data, ctx.pos, 3)?;
        let (key_wt, val_wt, count, mut p) =
            parse_map_header(body).ok_or_else(|| Error::parse("invalid WireMap header"))?;
        if key_wt != ctx.wire_types.key || val_wt != ctx.wire_types.val {
            return Err(Error::parse(format!(
                "WireMap header mismatch: expected ({}, {}), got ({key_wt}, {val_wt})",
                ctx.wire_types.key, ctx.wire_types.val
            )));
        }
        super::charge_typed_alloc(
            count.saturating_mul(core::mem::size_of::<(K, V)>().saturating_add(16)),
        )?;
        if ctx.reset {
            map.clear();
        }
        map.reserve(count.min(4096));
        for _ in 0..count {
            let (k, after_k) = read_key(body, p)?;
            let (v, after_v) = read_val(body, after_k, ctx.depth + 1)?;
            map.insert(k, v);
            p = after_v;
        }
        if p != body.len() {
            return Err(Error::parse("WireMap trailing bytes"));
        }
        Ok(next_pos)
    }

    /// Decodes a `WireMap` field into a `BTreeMap<K, V>`.
    pub fn read_btree_map_field<K, V, FK, FV>(
        map: &mut BTreeMap<K, V>,
        ctx: MapReadCtx<'_>,
        mut read_key: FK,
        mut read_val: FV,
    ) -> Result<usize>
    where
        K: Ord,
        FK: FnMut(&[u8], usize) -> Result<(K, usize)>,
        FV: FnMut(&[u8], usize, usize) -> Result<(V, usize)>,
    {
        if ctx.depth + 1 > MAX_NESTING_DEPTH {
            return Err(Error::DepthLimitExceeded(ctx.depth + 1));
        }
        let (body, next_pos) = read_container_slice(ctx.data, ctx.pos, 3)?;
        let (key_wt, val_wt, count, mut p) =
            parse_map_header(body).ok_or_else(|| Error::parse("invalid WireMap header"))?;
        if key_wt != ctx.wire_types.key || val_wt != ctx.wire_types.val {
            return Err(Error::parse(format!(
                "WireMap header mismatch: expected ({}, {}), got ({key_wt}, {val_wt})",
                ctx.wire_types.key, ctx.wire_types.val
            )));
        }
        super::charge_typed_alloc(
            count.saturating_mul(core::mem::size_of::<(K, V)>().saturating_add(16)),
        )?;
        if ctx.reset {
            map.clear();
        }
        for _ in 0..count {
            let (k, after_k) = read_key(body, p)?;
            let (v, after_v) = read_val(body, after_k, ctx.depth + 1)?;
            map.insert(k, v);
            p = after_v;
        }
        if p != body.len() {
            return Err(Error::parse("WireMap trailing bytes"));
        }
        Ok(next_pos)
    }

    /// Encodes an untagged `WireMap` container inside a parent `WireArray` or `WireMap`.
    pub fn write_hash_map_elem<K, V, S, FK, FV>(
        dst: &mut Vec<u8>,
        wire_types: MapWireTypes,
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
        let len_pos = dst.len();
        dst.extend_from_slice(&[0, 0, wire_types.key, wire_types.val]);
        append_varint(dst, map.len() as u64);
        if deterministic && map.len() > 1 {
            let mut entries: Vec<(&K, &V)> = map.iter().collect();
            entries.sort_unstable_by_key(|(ka, _)| *ka);
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

    /// Decodes an untagged `WireMap` container into a `HashMap<K, V, S>`.
    pub fn read_hash_map_elem<K, V, S, FK, FV>(
        data: &[u8],
        pos: usize,
        depth: usize,
        exp_key_wt: u8,
        exp_val_wt: u8,
        mut read_key: FK,
        mut read_val: FV,
    ) -> Result<(HashMap<K, V, S>, usize)>
    where
        K: Eq + Hash,
        S: Default + std::hash::BuildHasher,
        FK: FnMut(&[u8], usize) -> Result<(K, usize)>,
        FV: FnMut(&[u8], usize, usize) -> Result<(V, usize)>,
    {
        let mut map = HashMap::default();
        let next_pos = read_hash_map_field(
            &mut map,
            MapReadCtx {
                data,
                pos,
                depth,
                wire_types: MapWireTypes::new(exp_key_wt, exp_val_wt),
                reset: false,
            },
            &mut read_key,
            &mut read_val,
        )?;
        Ok((map, next_pos))
    }

    /// Encodes an untagged `BTreeMap<K, V>` container inside a parent `WireArray` or `WireMap`.
    pub fn write_btree_map_elem<K, V, FK, FV>(
        dst: &mut Vec<u8>,
        wire_types: MapWireTypes,
        map: &BTreeMap<K, V>,
        deterministic: bool,
        mut write_key: FK,
        mut write_val: FV,
    ) -> Result<()>
    where
        FK: FnMut(&mut Vec<u8>, &K) -> Result<()>,
        FV: FnMut(&mut Vec<u8>, &V, bool) -> Result<()>,
    {
        let len_pos = dst.len();
        dst.extend_from_slice(&[0, 0, wire_types.key, wire_types.val]);
        append_varint(dst, map.len() as u64);
        for (k, v) in map {
            write_key(dst, k)?;
            write_val(dst, v, deterministic)?;
        }
        backpatch_container_len(dst, len_pos);
        Ok(())
    }

    /// Decodes an untagged `WireMap` container into a `BTreeMap<K, V>`.
    pub fn read_btree_map_elem<K, V, FK, FV>(
        data: &[u8],
        pos: usize,
        depth: usize,
        exp_key_wt: u8,
        exp_val_wt: u8,
        mut read_key: FK,
        mut read_val: FV,
    ) -> Result<(BTreeMap<K, V>, usize)>
    where
        K: Ord,
        FK: FnMut(&[u8], usize) -> Result<(K, usize)>,
        FV: FnMut(&[u8], usize, usize) -> Result<(V, usize)>,
    {
        let mut map = BTreeMap::new();
        let next_pos = read_btree_map_field(
            &mut map,
            MapReadCtx {
                data,
                pos,
                depth,
                wire_types: MapWireTypes::new(exp_key_wt, exp_val_wt),
                reset: false,
            },
            &mut read_key,
            &mut read_val,
        )?;
        Ok((map, next_pos))
    }

    #[cfg(feature = "buffa")]
    impl<T: Default, P: ::buffa::ProtoBox<T>> IsEmpty for ::buffa::MessageField<T, P> {
        #[inline]
        fn is_omnibuf_empty(&self) -> bool {
            !self.is_set()
        }
    }

    #[cfg(feature = "buffa")]
    impl<E: ::buffa::Enumeration> IsEmpty for ::buffa::EnumValue<E> {
        #[inline]
        fn is_omnibuf_empty(&self) -> bool {
            self.to_i32() == 0
        }
    }

    /// Encodes a `buffa::MessageField<M, P>` if set.
    #[cfg(feature = "buffa")]
    #[inline]
    pub fn write_buffa_message_field<M: Message, P: ::buffa::ProtoBox<M>>(
        dst: &mut Vec<u8>,
        field_num: u32,
        field: &::buffa::MessageField<M, P>,
        deterministic: bool,
    ) -> Result<()> {
        if let Some(m) = field.as_option() {
            write_sub_msg_field(dst, field_num, m, deterministic)?;
        }
        Ok(())
    }

    /// Decodes a `WIRE_SUB_MSG` into a `buffa::MessageField<M, P>`, merging on repeat occurrences.
    #[cfg(feature = "buffa")]
    #[inline]
    pub fn read_buffa_message_field<M: Message, P: ::buffa::ProtoBox<M>>(
        slot: &mut ::buffa::MessageField<M, P>,
        data: &[u8],
        pos: usize,
        depth: usize,
        merge: bool,
    ) -> Result<usize> {
        let (sub_bytes, next_pos) = read_container_slice(data, pos, 0)?;
        if !merge || !slot.is_set() {
            super::charge_typed_alloc(core::mem::size_of::<M>())?;
            let mut m = M::default();
            m.decode_omnibuf_at_depth(sub_bytes, depth + 1, false)?;
            *slot = ::buffa::MessageField::some(m);
        } else {
            slot.get_or_insert_default()
                .decode_omnibuf_at_depth(sub_bytes, depth + 1, true)?;
        }
        Ok(next_pos)
    }

    /// Encodes a `buffa::EnumValue<E>` field as `WIRE_SINT`.
    #[cfg(feature = "buffa")]
    #[inline]
    pub fn write_buffa_enum_field<E: ::buffa::Enumeration>(
        dst: &mut Vec<u8>,
        field_num: u32,
        val: &::buffa::EnumValue<E>,
    ) {
        write_sint_field(dst, field_num, i64::from(val.to_i32()));
    }

    /// Decodes a `WIRE_SINT` scalar into a `buffa::EnumValue<E>`.
    #[cfg(feature = "buffa")]
    #[inline]
    pub fn read_buffa_enum_elem<E: ::buffa::Enumeration>(
        data: &[u8],
        pos: usize,
    ) -> Result<(::buffa::EnumValue<E>, usize)> {
        let (v, next_pos) = read_varint_at(data, pos)?;
        Ok((::buffa::EnumValue::from(decode_zigzag(v) as i32), next_pos))
    }

    /// Encodes `Vec<buffa::EnumValue<E>>` as `WireArray(WIRE_SINT)`.
    #[cfg(feature = "buffa")]
    #[inline]
    pub fn write_buffa_enum_vec_field<E: ::buffa::Enumeration>(
        dst: &mut Vec<u8>,
        field_num: u32,
        items: &[::buffa::EnumValue<E>],
    ) -> Result<()> {
        write_varint_vec_field(dst, field_num, WIRE_SINT, items, |v| {
            encode_zigzag(i64::from(v.to_i32()))
        })
    }

    /// Builds value-driven [`SchemaMeta`] for an optional `buffa::MessageField<M, P>` if present.
    #[cfg(feature = "buffa")]
    #[inline]
    pub fn buffa_message_field_value_schema_meta<M: Message, P: ::buffa::ProtoBox<M>>(
        field: &::buffa::MessageField<M, P>,
        depth: usize,
    ) -> Option<SchemaMeta> {
        field.as_option()?.build_value_schema_meta(depth)
    }

    /// Computes a strict lower-bound encoded byte size for a `buffa::MessageField<M, P>`.
    #[cfg(feature = "buffa")]
    #[inline]
    pub fn buffa_message_field_min_wire_size<M: Message, P: ::buffa::ProtoBox<M>>(
        field_num: u32,
        field: &::buffa::MessageField<M, P>,
        depth_rem: usize,
    ) -> usize {
        let Some(m) = field.as_option() else {
            return 0;
        };
        let tag_w = varint_len((u64::from(field_num) << 4) | u64::from(WIRE_SUB_MSG));
        let sub = if depth_rem > 0 {
            m.min_wire_size_bounded(depth_rem - 1)
        } else {
            0
        };
        tag_w + container_len_width(sub) + sub
    }
}
