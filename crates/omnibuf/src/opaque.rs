use crate::wire::{
    WIRE_ARRAY, WIRE_EXTENDED, WIRE_MAP, WIRE_SUB_MSG, fast_skip_value, read_tag_at, skip_value,
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

/// Splices unmodified contiguous byte ranges from `raw` into `dst` (appending after any
/// existing prefix in `dst`) and invokes `append_dirty` only for fields marked in `dirty_mask`.
///
/// Untouched fields are hopped in O(1) time using length prefixes without decoding their bodies.
/// If `dst`'s backing capacity aliases `raw`, `dst` is detached first so `raw` is never mutated.
pub fn splice_fields<F>(
    dst: &mut Vec<u8>,
    raw: &[u8],
    dirty_mask: u64,
    max_field: u16,
    mut append_dirty: F,
) where
    F: FnMut(&mut Vec<u8>, u16),
{
    let _keep_alive: Option<Vec<u8>> = if buffers_overlap(dst, raw) {
        let mut detached = Vec::with_capacity(dst.len() + raw.len() + 64);
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

        if fnum == 0 && wt != WIRE_SUB_MSG {
            break;
        }

        let next_pos = if matches!(wt, WIRE_ARRAY | WIRE_MAP | WIRE_EXTENDED) {
            match skip_value(raw, pos, wt) {
                Ok(next) => next,
                Err(_) => break,
            }
        } else {
            match fast_skip_value(raw, pos, wt) {
                Some(next) => next,
                None => break,
            }
        };

        pos = next_pos;
        let field_end = pos;
        valid_end = field_end;

        let bit = if fnum < 64 { 1u64 << fnum } else { 0 };
        if (dirty_mask & bit) != 0 {
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

    let rem = dirty_mask & !emitted;
    if rem != 0 {
        let limit = max_field.min(63);
        for fnum in 1..=limit {
            if (rem & (1u64 << fnum)) != 0 {
                append_dirty(dst, fnum);
            }
        }
    }
}

/// Allocates a new `Vec<u8>` containing the spliced output of `raw`.
#[inline]
pub fn splice_fields_vec<F>(raw: &[u8], dirty_mask: u64, max_field: u16, append_dirty: F) -> Vec<u8>
where
    F: FnMut(&mut Vec<u8>, u16),
{
    if dirty_mask == 0 {
        return raw.to_vec();
    }
    let mut out = Vec::with_capacity(raw.len() + 32);
    splice_fields(&mut out, raw, dirty_mask, max_field, append_dirty);
    out
}
