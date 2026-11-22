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
    append_varint, backpatch_container_len, backpatch_container_len_4b, cold_parse_err,
    container_len_width, decode_varint, decode_zigzag, encode_zigzag, fast_skip_value,
    grow_capacity, is_valid_utf8, parse_array_header, parse_array_header_typed, parse_map_header,
    put_varint_raw, read_len_slice, read_len_slice_opt, read_str_slice, read_varint_at,
    read_varint_at_opt, varint_len, write_bool_tagged, write_bytes_tagged, write_fixed_tagged,
    write_varint_tagged,
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
            meta.append_field0(dst);
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

    #[inline(always)]
    fn begin_tagged_container(dst: &mut Vec<u8>, field_num: u32, wire_type: u8) -> usize {
        let tag = (u64::from(field_num) << 4) | u64::from(wire_type & 0x0F);
        if tag <= 127 {
            let b0 = ((tag as u8) << 1) | 1;
            dst.reserve(3);
            unsafe {
                let len = dst.len();
                let ptr = dst.as_mut_ptr().add(len);
                *ptr = b0;
                *ptr.add(1) = 0;
                *ptr.add(2) = 0;
                dst.set_len(len + 3);
                len + 1
            }
        } else if tag <= 16_383 {
            let tb = (((tag as u16) << 2) | 2).to_le_bytes();
            dst.reserve(4);
            unsafe {
                let len = dst.len();
                let ptr = dst.as_mut_ptr().add(len);
                *ptr = tb[0];
                *ptr.add(1) = tb[1];
                *ptr.add(2) = 0;
                *ptr.add(3) = 0;
                dst.set_len(len + 4);
                len + 2
            }
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
            dst.reserve(5);
            unsafe {
                let len = dst.len();
                let ptr = dst.as_mut_ptr().add(len);
                *ptr = b0;
                core::ptr::write_bytes(ptr.add(1), 0, 4);
                dst.set_len(len + 5);
                len + 1
            }
        } else if tag <= 16_383 {
            let tb = (((tag as u16) << 2) | 2).to_le_bytes();
            dst.reserve(6);
            unsafe {
                let len = dst.len();
                let ptr = dst.as_mut_ptr().add(len);
                *ptr = tb[0];
                *ptr.add(1) = tb[1];
                core::ptr::write_bytes(ptr.add(2), 0, 4);
                dst.set_len(len + 6);
                len + 2
            }
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
        dst.reserve(9 + 3 + 9);
        unsafe {
            let len = dst.len();
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
                *slot = s.to_owned();
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
                *slot = b.to_vec();
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

    #[inline]
    pub fn write_sub_msg_field<M: Message>(
        dst: &mut Vec<u8>,
        field_num: u32,
        msg: &M,
        deterministic: bool,
    ) -> Result<()> {
        if dst.capacity() > 16_383 {
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
        let (sub_bytes, next_pos) = read_len_slice(data, pos, 0)?;
        match slot {
            None => {
                let msg = slot.insert(M::default());
                msg.decode_omnibuf_at_depth(sub_bytes, depth + 1, true)?;
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
        let (sub_bytes, next_pos) = read_len_slice(data, pos, 0)?;
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
            if lw == 4 {
                backpatch_container_len_4b(dst, len_pos);
            } else if lw == 2 {
                backpatch_container_len(dst, len_pos);
            }
        }
        Ok(())
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
        let (body, next_pos) = read_len_slice(data, pos, 2)?;
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
        let (body, next_pos) = read_len_slice(data, pos, 2)?;
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
        let (body, next_pos) = read_len_slice(data, pos, 2)?;
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
        for _ in 0..count {
            let Some((raw, next_p)) = read_len_slice_opt(body, p, 0) else {
                return Err(cold_parse_err("invalid container byteLen"));
            };
            if !is_valid_utf8(raw) {
                return Err(Error::InvalidUtf8);
            }
            // SAFETY: `is_valid_utf8(raw)` verified `raw` is valid UTF-8.
            let s = unsafe { core::str::from_utf8_unchecked(raw) }.to_owned();
            // SAFETY: `items` reserved space for at least `base + count` elements.
            unsafe {
                ptr.add(guard.len).write(s);
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
        let (body, next_pos) = read_len_slice(data, pos, 2)?;
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
        if dst.capacity() > 16_383 && count > 0 {
            if count <= 32 {
                let mut elem_mins = [0usize; 32];
                let mut elems_min = 0usize;
                for (slot, m) in elem_mins[..count].iter_mut().zip(items.iter()) {
                    let em = m.min_wire_size();
                    *slot = em;
                    elems_min =
                        elems_min.saturating_add(container_len_width(em).saturating_add(em));
                }
                let min_body = 1usize
                    .saturating_add(varint_len(count as u64))
                    .saturating_add(elems_min);
                if min_body > 16_383 {
                    dst.reserve(min_body.saturating_add(64));
                    let len_pos = begin_tagged_array_4b(dst, field_num, WIRE_SUB_MSG, count);
                    for (item, &em) in items.iter().zip(elem_mins[..count].iter()) {
                        write_sub_msg_elem_with_min(dst, item, em, deterministic)?;
                    }
                    backpatch_container_len_4b(dst, len_pos);
                    return Ok(());
                }
            } else {
                let elems_min: usize = items
                    .iter()
                    .map(|m| {
                        let em = m.min_wire_size();
                        container_len_width(em).saturating_add(em)
                    })
                    .fold(0usize, usize::saturating_add);
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
        }
        let len_pos = begin_tagged_array(dst, field_num, WIRE_SUB_MSG, count);
        for item in items {
            let elem_pos = dst.len();
            dst.extend_from_slice(&[0u8, 0u8]);
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
        let count = items.len();
        if dst.capacity() > 16_383 && count > 0 {
            if count <= 32 {
                let mut elem_mins = [0usize; 32];
                let mut elems_min = 0usize;
                for (slot, m) in elem_mins[..count].iter_mut().zip(items.iter()) {
                    let em = m.min_wire_size();
                    *slot = em;
                    elems_min =
                        elems_min.saturating_add(container_len_width(em).saturating_add(em));
                }
                let min_body = 1usize
                    .saturating_add(varint_len(count as u64))
                    .saturating_add(elems_min);
                if min_body > 16_383 {
                    dst.reserve(min_body.saturating_add(24));
                    let len_pos = begin_tagged_array_4b(dst, field_num, WIRE_SUB_MSG, count);
                    for (item, &em) in items.iter().zip(elem_mins[..count].iter()) {
                        write_sub_msg_elem_with_min(dst, item.as_ref(), em, deterministic)?;
                    }
                    backpatch_container_len_4b(dst, len_pos);
                    return Ok(());
                }
            } else {
                let elems_min: usize = items
                    .iter()
                    .map(|m| {
                        let em = m.min_wire_size();
                        container_len_width(em).saturating_add(em)
                    })
                    .fold(0usize, usize::saturating_add);
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
        }
        let len_pos = begin_tagged_array(dst, field_num, WIRE_SUB_MSG, count);
        for item in items {
            let elem_pos = dst.len();
            dst.extend_from_slice(&[0u8, 0u8]);
            item.encode_omnibuf_append(dst, deterministic)?;
            backpatch_container_len(dst, elem_pos);
        }
        backpatch_container_len(dst, len_pos);
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
            let (elem_bytes, next_p) = read_len_slice(body, p, 0)?;
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
        let (body, next_pos) = read_len_slice(data, pos, 2)?;
        if reset {
            items.clear();
        }
        let (count, mut p) = parse_array_header_typed(body, WIRE_SUB_MSG)
            .ok_or_else(|| cold_parse_err("invalid WireArray(WireSubMsg) header"))?;
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
            let Some((elem_bytes, next_p)) = read_len_slice_opt(body, p, 0) else {
                return Err(cold_parse_err("invalid container byteLen"));
            };
            // SAFETY: `items` reserved space for at least `base + count` elements.
            // We write `M::default()` and advance `guard.len` before decoding so any
            // error or panic cleanly drops the initialized element.
            unsafe {
                let slot = ptr.add(guard.len);
                slot.write(M::default());
                guard.len += 1;
                (*slot).decode_omnibuf_at_depth(elem_bytes, depth + 2, true)?;
            }
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
        let (body, next_pos) = read_len_slice(data, pos, 2)?;
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
            let (elem_bytes, next_p) = read_len_slice(body, p, 0)?;
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
            dst.extend_from_slice(&[0, 0]);
            msg.encode_omnibuf_append(dst, deterministic)?;
            backpatch_container_len(dst, elem_pos);
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
        let min_sub = if dst.capacity() > 16_383 {
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
        let (elem_bytes, next_p) = read_len_slice(body, p, 0)?;
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
        let (elem_bytes, next_p) = read_len_slice(body, p, 0)?;
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
        let (body, next_pos) = read_len_slice(data, pos, 2)?;
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
        let (body, next_pos) = read_len_slice(data, pos, 2)?;
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
        let end = p
            .checked_add(4)
            .ok_or_else(|| cold_parse_err("truncated fixed32 element"))?;
        let raw: [u8; 4] = body
            .get(p..end)
            .ok_or_else(|| cold_parse_err("truncated fixed32 element"))?
            .try_into()
            .unwrap();
        Ok((u32::from_le_bytes(raw), end))
    }

    #[inline(always)]
    pub fn read_elem_fixed64(body: &[u8], p: usize) -> Result<(u64, usize)> {
        let end = p
            .checked_add(8)
            .ok_or_else(|| cold_parse_err("truncated fixed64 element"))?;
        let raw: [u8; 8] = body
            .get(p..end)
            .ok_or_else(|| cold_parse_err("truncated fixed64 element"))?
            .try_into()
            .unwrap();
        Ok((u64::from_le_bytes(raw), end))
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
        let (s, next_p) = read_str_slice(body, p)?;
        Ok((s.to_owned(), next_p))
    }

    #[inline(always)]
    pub fn read_elem_bytes(body: &[u8], p: usize) -> Result<(Vec<u8>, usize)> {
        let (b, next_p) = read_len_slice(body, p, 0)?;
        Ok((b.to_vec(), next_p))
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
        let (sub_bytes, next_pos) = read_len_slice(data, pos, 0)?;
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
        let (sub_bytes, next_pos) = read_len_slice(data, pos, 0)?;
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
        let (body, next_pos) = read_len_slice(data, pos, 2)?;
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
        let (body, next_pos) = read_len_slice(data, pos, 2)?;
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
            let (elem_bytes, next_p) = read_len_slice(body, p, 0)?;
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

    #[allow(clippy::too_many_arguments)]
    pub fn read_hash_map_borrowed_field<'de, K, V, S, FK, FV>(
        map: &mut HashMap<K, V, S>,
        data: &'de [u8],
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
        FK: FnMut(&'de [u8], usize) -> Result<(K, usize)>,
        FV: FnMut(&'de [u8], usize, usize) -> Result<(V, usize)>,
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
        super::charge_typed_alloc(
            count.saturating_mul(core::mem::size_of::<(K, V)>().saturating_add(16)),
        )?;
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
        let count = map.len();
        let min_body = 2usize
            .saturating_add(varint_len(count as u64))
            .saturating_add(count.saturating_mul(2));
        append_tag(dst, field_num, WIRE_MAP);
        let len_pos = dst.len();
        let use_4b = min_body > 16_383;
        if use_4b {
            dst.reserve(min_body.saturating_add(24));
            dst.extend_from_slice(&[0, 0, 0, 0, key_wt, val_wt]);
        } else {
            dst.extend_from_slice(&[0, 0, key_wt, val_wt]);
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
        let count = map.len();
        let min_body = 2usize
            .saturating_add(varint_len(count as u64))
            .saturating_add(count.saturating_mul(2));
        append_tag(dst, field_num, WIRE_MAP);
        let len_pos = dst.len();
        let use_4b = min_body > 16_383;
        if use_4b {
            dst.reserve(min_body.saturating_add(24));
            dst.extend_from_slice(&[0, 0, 0, 0, key_wt, val_wt]);
        } else {
            dst.extend_from_slice(&[0, 0, key_wt, val_wt]);
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
        super::charge_typed_alloc(
            count.saturating_mul(core::mem::size_of::<(K, V)>().saturating_add(16)),
        )?;
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
        super::charge_typed_alloc(
            count.saturating_mul(core::mem::size_of::<(K, V)>().saturating_add(16)),
        )?;
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

    /// Encodes an untagged `WireMap` container inside a parent `WireArray` or `WireMap`.
    #[allow(clippy::too_many_arguments)]
    pub fn write_hash_map_elem<K, V, S, FK, FV>(
        dst: &mut Vec<u8>,
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
        let len_pos = dst.len();
        dst.extend_from_slice(&[0, 0, key_wt, val_wt]);
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
            data,
            pos,
            depth,
            exp_key_wt,
            exp_val_wt,
            false,
            &mut read_key,
            &mut read_val,
        )?;
        Ok((map, next_pos))
    }

    /// Encodes an untagged `BTreeMap<K, V>` container inside a parent `WireArray` or `WireMap`.
    pub fn write_btree_map_elem<K, V, FK, FV>(
        dst: &mut Vec<u8>,
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
            data,
            pos,
            depth,
            exp_key_wt,
            exp_val_wt,
            false,
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
        let (sub_bytes, next_pos) = read_len_slice(data, pos, 0)?;
        if !merge || !slot.is_set() {
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
