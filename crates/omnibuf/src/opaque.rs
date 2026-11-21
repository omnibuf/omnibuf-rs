use core::cell::{Cell, OnceCell};
use std::borrow::Cow;

use crate::error::{Error, Result};
use crate::field0::validate_field0;
use crate::wire::{
    WIRE_ARRAY, WIRE_BOOL_FALSE, WIRE_BOOL_TRUE, WIRE_BYTES, WIRE_FIXED32, WIRE_FIXED64,
    WIRE_FLOAT32, WIRE_FLOAT64, WIRE_SFIXED32, WIRE_SFIXED64, WIRE_SINT, WIRE_STRING, WIRE_SUB_MSG,
    WIRE_UINT, decode_varint, decode_zigzag, locate_field_mask, next_container_field,
    parse_array_header, read_len_slice, read_str_slice, read_sub_msg, read_tag_at, skip_value_opt,
    sub_msg_arr_len, validate_message, validate_value,
};

#[inline]
fn buffers_overlap(dst: &Vec<u8>, raw: &[u8]) -> bool {
    if raw.is_empty() || dst.capacity() == 0 {
        return false;
    }
    let dst_start = dst.as_ptr() as usize;
    let dst_end = dst_start.saturating_add(dst.capacity());
    let raw_start = raw.as_ptr() as usize;
    let raw_end = raw_start.saturating_add(raw.len());
    dst_start < raw_end && raw_start < dst_end
}

/// Replaces `dst`'s contents with a copy of `raw`, detaching `dst` if its backing
/// allocation overlaps `raw`.
#[inline]
pub fn copy_packet(dst: &mut Vec<u8>, raw: &[u8]) {
    if buffers_overlap(dst, raw) {
        let copy = raw.to_vec();
        let _keep_alive = core::mem::replace(dst, copy);
        return;
    }
    dst.clear();
    dst.extend_from_slice(raw);
}

/// Validates `raw` and replaces `dst`'s contents with a copy of `raw`.
#[inline]
pub fn try_copy_packet(dst: &mut Vec<u8>, raw: &[u8]) -> Result<()> {
    validate_message(raw, 0)?;
    copy_packet(dst, raw);
    Ok(())
}

/// Appends `raw` to `dst` while preserving any existing framing prefix in `dst`,
/// detaching `dst` first if its backing allocation overlaps `raw`.
#[inline]
pub fn append_packet(dst: &mut Vec<u8>, raw: &[u8]) {
    if buffers_overlap(dst, raw) {
        let mut detached = Vec::with_capacity(dst.len().saturating_add(raw.len()));
        detached.extend_from_slice(dst);
        detached.extend_from_slice(raw);
        let _keep_alive = core::mem::replace(dst, detached);
        return;
    }
    dst.extend_from_slice(raw);
}

/// Validates `raw` and appends it to `dst` while preserving any existing prefix in `dst`.
#[inline]
pub fn try_append_packet(dst: &mut Vec<u8>, raw: &[u8]) -> Result<()> {
    validate_message(raw, 0)?;
    append_packet(dst, raw);
    Ok(())
}

/// Splices unmodified contiguous byte ranges from `raw` into `dst` (appending after any
/// existing prefix in `dst`) and invokes `append_dirty` only for fields marked in `dirty_mask`.
///
/// Untouched fields are hopped in O(1) time using length prefixes without decoding their bodies.
/// If `dst`'s backing capacity aliases `raw`, `dst` is detached first so `raw` is never mutated.
#[inline]
pub fn splice_fields<F>(
    dst: &mut Vec<u8>,
    raw: &[u8],
    dirty_mask: u64,
    max_field: u16,
    mut append_dirty: F,
) where
    F: FnMut(&mut Vec<u8>, u16),
{
    let user_mask = dirty_mask & !1u64;
    let _keep_alive: Option<Vec<u8>> = if buffers_overlap(dst, raw) {
        let cap = dst.len().saturating_add(raw.len()).saturating_add(64);
        let mut detached = Vec::with_capacity(cap);
        detached.extend_from_slice(dst);
        Some(core::mem::replace(dst, detached))
    } else {
        None
    };

    let n = raw.len();
    let mut pos = 0usize;
    let mut clean_start = 0usize;
    let mut valid_end = 0usize;
    let mut emitted = 0u64;

    while pos < n {
        let field_start = pos;
        let Some((fnum, wt, after_tag)) = read_tag_at(raw, pos) else {
            break;
        };
        pos = after_tag;

        let next_pos = if fnum == 0 {
            if wt != WIRE_SUB_MSG {
                break;
            }
            let Ok(end) = validate_field0(raw, pos, 0) else {
                break;
            };
            end
        } else {
            let Some(end) = skip_value_opt(raw, pos, wt) else {
                break;
            };
            end
        };

        pos = next_pos;
        let field_end = pos;
        valid_end = field_end;

        let bit = if fnum > 0 && fnum < 64 {
            1u64 << fnum
        } else {
            0
        };
        if (user_mask & bit) != 0 {
            if clean_start < field_start {
                dst.extend_from_slice(&raw[clean_start..field_start]);
            }
            if (emitted & bit) == 0 {
                append_dirty(dst, fnum as u16);
                emitted |= bit;
            }
            clean_start = field_end;
        } else {
            emitted |= bit;
        }
    }

    if clean_start < valid_end {
        dst.extend_from_slice(&raw[clean_start..valid_end]);
    }

    let rem = user_mask & !emitted;
    if rem != 0 {
        let limit = max_field.min(63);
        for fnum in 1..=limit {
            if (rem & (1u64 << fnum)) != 0 {
                append_dirty(dst, fnum);
            }
        }
    }
}

/// Fallible counterpart to [`splice_fields`] that validates every field in `raw` and returns
/// `Err` (leaving `dst` at its original length) if `raw` contains any malformed tag or payload.
pub fn try_splice_fields<F>(
    dst: &mut Vec<u8>,
    raw: &[u8],
    dirty_mask: u64,
    max_field: u16,
    mut append_dirty: F,
) -> Result<()>
where
    F: FnMut(&mut Vec<u8>, u16),
{
    let user_mask = dirty_mask & !1u64;
    let _keep_alive: Option<Vec<u8>> = if buffers_overlap(dst, raw) {
        let cap = dst.len().saturating_add(raw.len()).saturating_add(64);
        let mut detached = Vec::with_capacity(cap);
        detached.extend_from_slice(dst);
        Some(core::mem::replace(dst, detached))
    } else {
        None
    };

    let orig_len = dst.len();
    let n = raw.len();
    let mut pos = 0usize;
    let mut clean_start = 0usize;
    let mut emitted = 0u64;

    while pos < n {
        let field_start = pos;
        let Some((fnum, wt, after_tag)) = read_tag_at(raw, pos) else {
            dst.truncate(orig_len);
            return Err(Error::parse(format!("invalid or truncated tag at {pos}")));
        };
        pos = after_tag;

        let field_end = if fnum == 0 {
            if wt != WIRE_SUB_MSG {
                dst.truncate(orig_len);
                return Err(Error::parse(format!("invalid Field #0 wire type {wt}")));
            }
            match validate_field0(raw, pos, 0) {
                Ok(end) => end,
                Err(err) => {
                    dst.truncate(orig_len);
                    return Err(err);
                }
            }
        } else {
            match validate_value(raw, pos, wt, 0) {
                Ok(end) => end,
                Err(err) => {
                    dst.truncate(orig_len);
                    return Err(err);
                }
            }
        };

        pos = field_end;
        let bit = if fnum > 0 && fnum < 64 {
            1u64 << fnum
        } else {
            0
        };
        if (user_mask & bit) != 0 {
            if clean_start < field_start {
                dst.extend_from_slice(&raw[clean_start..field_start]);
            }
            if (emitted & bit) == 0 {
                append_dirty(dst, fnum as u16);
                emitted |= bit;
            }
            clean_start = field_end;
        } else {
            emitted |= bit;
        }
    }

    if clean_start < n {
        dst.extend_from_slice(&raw[clean_start..n]);
    }

    let rem = user_mask & !emitted;
    if rem != 0 {
        let limit = max_field.min(63);
        for fnum in 1..=limit {
            if (rem & (1u64 << fnum)) != 0 {
                append_dirty(dst, fnum);
            }
        }
    }
    Ok(())
}

/// Allocates a new `Vec<u8>` containing the spliced output of `raw`.
#[inline]
pub fn splice_fields_vec<F>(raw: &[u8], dirty_mask: u64, max_field: u16, append_dirty: F) -> Vec<u8>
where
    F: FnMut(&mut Vec<u8>, u16),
{
    if (dirty_mask & !1u64) == 0 {
        return raw.to_vec();
    }
    let mut out = Vec::with_capacity(raw.len().saturating_add(32));
    splice_fields(&mut out, raw, dirty_mask, max_field, append_dirty);
    out
}

/// Fallible counterpart to [`splice_fields_vec`] that validates `raw` and returns `Err` on malformed wire bytes.
pub fn try_splice_fields_vec<F>(
    raw: &[u8],
    dirty_mask: u64,
    max_field: u16,
    append_dirty: F,
) -> Result<Vec<u8>>
where
    F: FnMut(&mut Vec<u8>, u16),
{
    if (dirty_mask & !1u64) == 0 {
        validate_message(raw, 0)?;
        return Ok(raw.to_vec());
    }
    let mut out = Vec::with_capacity(raw.len().saturating_add(32));
    try_splice_fields(&mut out, raw, dirty_mask, max_field, append_dirty)?;
    Ok(out)
}

/// Top-level field-offset directory for O(1) multi-field reads on `Opaque` views (`1..=63`).
#[derive(Clone, Debug)]
struct FieldDir {
    offsets: [u32; 64],
    wts: [u8; 64],
    present_mask: u64,
    multi_wt_mask: u64,
    dup_sub_msg_mask: u64,
    valid: bool,
    use_fallback: bool,
}

impl FieldDir {
    fn scan(packet: &[u8]) -> Self {
        if packet.len() >= u32::MAX as usize {
            return Self {
                offsets: [u32::MAX; 64],
                wts: [0; 64],
                present_mask: 0,
                multi_wt_mask: 0,
                dup_sub_msg_mask: 0,
                valid: true,
                use_fallback: true,
            };
        }
        let mut dir = Self {
            offsets: [u32::MAX; 64],
            wts: [0; 64],
            present_mask: 0,
            multi_wt_mask: 0,
            dup_sub_msg_mask: 0,
            valid: false,
            use_fallback: false,
        };
        let mut pos = 0usize;
        let n = packet.len();
        while pos < n {
            let Some((fnum, wt, next_pos)) = read_tag_at(packet, pos) else {
                return dir;
            };
            pos = next_pos;
            if fnum == 0 {
                if wt != WIRE_SUB_MSG {
                    return dir;
                }
                let Ok(end) = validate_field0(packet, pos, 0) else {
                    return dir;
                };
                pos = end;
                continue;
            }
            if fnum < 64 {
                let idx = fnum as usize;
                let bit = 1u64 << fnum;
                if (dir.present_mask & bit) != 0 {
                    if dir.wts[idx] != wt {
                        dir.multi_wt_mask |= bit;
                    } else if wt == WIRE_SUB_MSG {
                        dir.dup_sub_msg_mask |= bit;
                    }
                }
                dir.present_mask |= bit;
                dir.offsets[idx] = pos as u32;
                dir.wts[idx] = wt;
            }
            let Some(end) = skip_value_opt(packet, pos, wt) else {
                return dir;
            };
            pos = end;
        }
        dir.valid = true;
        dir
    }

    #[inline]
    fn locate_mask<'a>(
        &self,
        packet: &'a [u8],
        fnum: u16,
        exp_mask: u16,
    ) -> Option<(&'a [u8], u8)> {
        if self.use_fallback || fnum == 0 || fnum >= 64 {
            return locate_field_mask(packet, fnum, exp_mask);
        }
        if !self.valid {
            return None;
        }
        let bit = 1u64 << fnum;
        if (self.present_mask & bit) == 0 {
            return None;
        }
        if (self.multi_wt_mask & bit) != 0 {
            return locate_field_mask(packet, fnum, exp_mask);
        }
        let wt = self.wts[fnum as usize];
        if (exp_mask & (1u16 << wt)) == 0 {
            return None;
        }
        let off = self.offsets[fnum as usize] as usize;
        Some((&packet[off..], wt))
    }

    #[inline]
    fn read_sub_msg<'a>(&self, packet: &'a [u8], fnum: u16) -> Option<Cow<'a, [u8]>> {
        if self.use_fallback || fnum == 0 || fnum >= 64 {
            return read_sub_msg(packet, fnum);
        }
        if !self.valid {
            return None;
        }
        let bit = 1u64 << fnum;
        if (self.present_mask & bit) == 0 {
            return None;
        }
        if ((self.multi_wt_mask | self.dup_sub_msg_mask) & bit) != 0 {
            return read_sub_msg(packet, fnum);
        }
        if self.wts[fnum as usize] != WIRE_SUB_MSG {
            return None;
        }
        let off = self.offsets[fnum as usize] as usize;
        let (slice, _) = read_len_slice(packet, off, 0).ok()?;
        Some(Cow::Borrowed(slice))
    }
}

/// Lazy top-level field-offset directory embedded inside generated `Opaque<Msg>` views.
///
/// Single-field and two-field lookups scan directly with zero heap allocations; once three
/// or more fields are queried on the same view, headers are indexed once for O(1) access.
#[derive(Clone, Debug, Default)]
pub struct LazyFieldDir {
    reads: Cell<u8>,
    cell: OnceCell<Box<FieldDir>>,
}

impl LazyFieldDir {
    /// Creates an empty `LazyFieldDir`.
    #[inline]
    pub const fn new() -> Self {
        Self {
            reads: Cell::new(0),
            cell: OnceCell::new(),
        }
    }

    /// Invalidates any cached offsets when the underlying `raw` buffer changes.
    #[inline]
    pub fn reset(&mut self) {
        self.reads.set(0);
        let _ = self.cell.take();
    }

    #[inline]
    pub fn locate_mask<'a>(
        &self,
        packet: &'a [u8],
        field_num: u16,
        exp_mask: u16,
    ) -> Option<(&'a [u8], u8)> {
        if let Some(dir) = self.cell.get() {
            return dir.locate_mask(packet, field_num, exp_mask);
        }
        let count = self.reads.get();
        if count < 2 {
            self.reads.set(count + 1);
            return locate_field_mask(packet, field_num, exp_mask);
        }
        let dir = self.cell.get_or_init(|| Box::new(FieldDir::scan(packet)));
        dir.locate_mask(packet, field_num, exp_mask)
    }

    #[inline]
    pub fn read_uint(&self, packet: &[u8], field_num: u16) -> Option<u64> {
        let (s, _) = self.locate_mask(packet, field_num, 1 << WIRE_UINT)?;
        decode_varint(s).map(|(v, _)| v)
    }

    #[inline]
    pub fn read_sint(&self, packet: &[u8], field_num: u16) -> Option<i64> {
        let (s, _) = self.locate_mask(packet, field_num, 1 << WIRE_SINT)?;
        decode_varint(s).map(|(v, _)| decode_zigzag(v))
    }

    #[inline]
    pub fn read_bool(&self, packet: &[u8], field_num: u16) -> Option<bool> {
        let (_, wt) = self.locate_mask(
            packet,
            field_num,
            (1 << WIRE_BOOL_FALSE) | (1 << WIRE_BOOL_TRUE),
        )?;
        Some(wt == WIRE_BOOL_TRUE)
    }

    #[inline]
    pub fn read_fixed32(&self, packet: &[u8], field_num: u16) -> Option<u32> {
        let (s, _) = self.locate_mask(packet, field_num, 1 << WIRE_FIXED32)?;
        let raw: [u8; 4] = s.get(..4)?.try_into().ok()?;
        Some(u32::from_le_bytes(raw))
    }

    #[inline]
    pub fn read_fixed64(&self, packet: &[u8], field_num: u16) -> Option<u64> {
        let (s, _) = self.locate_mask(packet, field_num, 1 << WIRE_FIXED64)?;
        let raw: [u8; 8] = s.get(..8)?.try_into().ok()?;
        Some(u64::from_le_bytes(raw))
    }

    #[inline]
    pub fn read_sfixed32(&self, packet: &[u8], field_num: u16) -> Option<i32> {
        let (s, _) = self.locate_mask(packet, field_num, 1 << WIRE_SFIXED32)?;
        let raw: [u8; 4] = s.get(..4)?.try_into().ok()?;
        Some(i32::from_le_bytes(raw))
    }

    #[inline]
    pub fn read_sfixed64(&self, packet: &[u8], field_num: u16) -> Option<i64> {
        let (s, _) = self.locate_mask(packet, field_num, 1 << WIRE_SFIXED64)?;
        let raw: [u8; 8] = s.get(..8)?.try_into().ok()?;
        Some(i64::from_le_bytes(raw))
    }

    #[inline]
    pub fn read_float32(&self, packet: &[u8], field_num: u16) -> Option<f32> {
        let (s, _) = self.locate_mask(packet, field_num, 1 << WIRE_FLOAT32)?;
        let raw: [u8; 4] = s.get(..4)?.try_into().ok()?;
        Some(f32::from_bits(u32::from_le_bytes(raw)))
    }

    #[inline]
    pub fn read_float64(&self, packet: &[u8], field_num: u16) -> Option<f64> {
        let (s, _) = self.locate_mask(packet, field_num, 1 << WIRE_FLOAT64)?;
        let raw: [u8; 8] = s.get(..8)?.try_into().ok()?;
        Some(f64::from_bits(u64::from_le_bytes(raw)))
    }

    #[inline]
    pub fn read_str<'a>(&self, packet: &'a [u8], field_num: u16) -> Option<&'a str> {
        let (s, _) = self.locate_mask(packet, field_num, 1 << WIRE_STRING)?;
        let (str_ref, _) = read_str_slice(s, 0).ok()?;
        Some(str_ref)
    }

    #[inline]
    pub fn read_bytes<'a>(&self, packet: &'a [u8], field_num: u16) -> Option<&'a [u8]> {
        let (s, _) = self.locate_mask(packet, field_num, 1 << WIRE_BYTES)?;
        let (bytes, _) = read_len_slice(s, 0, 0).ok()?;
        Some(bytes)
    }

    #[inline]
    pub fn read_sub_msg<'a>(&self, packet: &'a [u8], field_num: u16) -> Option<Cow<'a, [u8]>> {
        if let Some(dir) = self.cell.get() {
            return dir.read_sub_msg(packet, field_num);
        }
        let count = self.reads.get();
        if count < 2 {
            self.reads.set(count + 1);
            return read_sub_msg(packet, field_num);
        }
        let dir = self.cell.get_or_init(|| Box::new(FieldDir::scan(packet)));
        dir.read_sub_msg(packet, field_num)
    }

    #[inline]
    pub fn has_sub_msg(&self, packet: &[u8], field_num: u16) -> bool {
        self.locate_mask(packet, field_num, 1 << WIRE_SUB_MSG)
            .is_some()
    }
}

/// Zero-allocation linear iterator over raw `WireArray(WireSubMsg)` element slices.
#[derive(Clone, Debug)]
pub struct SubMsgArrIter<'a> {
    packet: &'a [u8],
    field_num: u16,
    pkt_pos: usize,
    seg_body: &'a [u8],
    seg_pos: usize,
    seg_rem: usize,
    rem_total: usize,
}

impl<'a> SubMsgArrIter<'a> {
    /// Creates a linear iterator over all `WireArray(WireSubMsg)` elements for `field_num`.
    #[inline]
    pub fn new(packet: &'a [u8], field_num: u16) -> Self {
        let total = sub_msg_arr_len(packet, field_num);
        Self {
            packet,
            field_num,
            pkt_pos: 0,
            seg_body: &[],
            seg_pos: 0,
            seg_rem: 0,
            rem_total: total,
        }
    }
}

impl<'a> Iterator for SubMsgArrIter<'a> {
    type Item = &'a [u8];

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.rem_total == 0 {
            return None;
        }
        while self.seg_rem == 0 {
            let (matched, valid) = next_container_field(
                self.packet,
                self.pkt_pos,
                self.field_num,
                WIRE_ARRAY,
                2,
                false,
            );
            if !valid {
                self.rem_total = 0;
                return None;
            }
            let Some((body, next_pos)) = matched else {
                self.rem_total = 0;
                return None;
            };
            self.pkt_pos = next_pos;
            let Some((elem_wt, count, p)) = parse_array_header(body) else {
                self.rem_total = 0;
                return None;
            };
            if elem_wt != WIRE_SUB_MSG {
                self.rem_total = 0;
                return None;
            }
            self.seg_body = body;
            self.seg_pos = p;
            self.seg_rem = count;
        }
        let Ok((slice, next_p)) = read_len_slice(self.seg_body, self.seg_pos, 0) else {
            self.rem_total = 0;
            return None;
        };
        self.seg_pos = next_p;
        self.seg_rem -= 1;
        self.rem_total -= 1;
        Some(slice)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.rem_total, Some(self.rem_total))
    }
}

impl ExactSizeIterator for SubMsgArrIter<'_> {}

/// Iterator over a repeated sub-message field on an `Opaque` view in either clean or dirty state.
pub enum OpaqueSubMsgIter<'a, T, Out, FR, FD> {
    Clean(
        SubMsgArrIter<'a>,
        FR,
        core::marker::PhantomData<fn(&T) -> Out>,
    ),
    Dirty(core::slice::Iter<'a, T>, FD),
}

impl<'a, T, Out, FR, FD> OpaqueSubMsgIter<'a, T, Out, FR, FD>
where
    FR: FnMut(&'a [u8]) -> Out,
    FD: FnMut(&'a T) -> Out,
{
    #[inline]
    pub fn clean(packet: &'a [u8], field_num: u16, map_raw: FR) -> Self {
        Self::Clean(
            SubMsgArrIter::new(packet, field_num),
            map_raw,
            core::marker::PhantomData,
        )
    }

    #[inline]
    pub fn dirty(items: &'a [T], map_dirty: FD) -> Self {
        Self::Dirty(items.iter(), map_dirty)
    }
}

impl<'a, T, Out, FR, FD> Iterator for OpaqueSubMsgIter<'a, T, Out, FR, FD>
where
    FR: FnMut(&'a [u8]) -> Out,
    FD: FnMut(&'a T) -> Out,
{
    type Item = Out;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Clean(iter, f, _) => iter.next().map(f),
            Self::Dirty(iter, f) => iter.next().map(f),
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::Clean(iter, _, _) => iter.size_hint(),
            Self::Dirty(iter, _) => iter.size_hint(),
        }
    }
}

impl<'a, T, Out, FR, FD> ExactSizeIterator for OpaqueSubMsgIter<'a, T, Out, FR, FD>
where
    FR: FnMut(&'a [u8]) -> Out,
    FD: FnMut(&'a T) -> Out,
{
}
