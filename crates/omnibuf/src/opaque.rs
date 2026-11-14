use crate::error::{Error, Result};
use crate::field0::validate_field0;
use crate::wire::{WIRE_SUB_MSG, read_tag_at, skip_value_opt, validate_message, validate_value};

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
