use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::wire::{
    MAX_FIELD_NUMBER, MAX_NESTING_DEPTH, WIRE_MAP, WIRE_STRING, WIRE_SUB_MSG, WIRE_UINT,
    append_varint, backpatch_container_len, decode_varint, parse_map_header, read_len_slice,
    read_str_slice, read_tag_at, skip_value_opt, validate_value_with_max_depth,
};

/// Optional inline schema header encoded as `Field #0` (`Tag = 0x19`, `WireSubMsg = 12`)
/// inside an OmniBuf message (`omnibuf.v1.SchemaMeta`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SchemaMeta {
    pub type_name: String,
    pub fields: BTreeMap<u32, String>,
    pub children: BTreeMap<u32, SchemaMeta>,
}

impl SchemaMeta {
    /// Appends `Field #0` (`Tag = 0x19`, `WireSubMsg = 12`) encoding `self` to `dst`.
    ///
    /// `BTreeMap` stores keys in ascending order, producing deterministic wire output.
    pub fn append_field0(&self, dst: &mut Vec<u8>) {
        dst.push((WIRE_SUB_MSG << 1) | 1); // 0x19
        let len_pos = dst.len();
        dst.extend_from_slice(&[0, 0]);
        self.append_body(dst);
        backpatch_container_len(dst, len_pos);
    }

    /// Encodes `Field #0` (`Tag = 0x19`, `WireSubMsg = 12`) into a new `Vec<u8>`.
    pub fn encode_field0(&self) -> Vec<u8> {
        let mut dst = Vec::with_capacity(128);
        self.append_field0(&mut dst);
        dst
    }

    fn append_body(&self, dst: &mut Vec<u8>) {
        // Field #1: type_name (WireString = 10 -> Tag 0x35)
        if !self.type_name.is_empty() {
            dst.push((((1 << 4) | WIRE_STRING) << 1) | 1);
            append_varint(dst, self.type_name.len() as u64);
            dst.extend_from_slice(self.type_name.as_bytes());
        }
        // Field #2: fields map<uint32, string> (WireMap = 14 -> Tag 0x5D)
        if !self.fields.is_empty() {
            dst.push((((2 << 4) | WIRE_MAP) << 1) | 1);
            let len_pos = dst.len();
            dst.extend_from_slice(&[0, 0, WIRE_UINT, WIRE_STRING]);
            append_varint(dst, self.fields.len() as u64);
            for (&k, name) in &self.fields {
                append_varint(dst, u64::from(k));
                append_varint(dst, name.len() as u64);
                dst.extend_from_slice(name.as_bytes());
            }
            backpatch_container_len(dst, len_pos);
        }
        // Field #3: children map<uint32, SchemaMeta> (WireMap = 14 -> Tag 0x7D)
        if !self.children.is_empty() {
            dst.push((((3 << 4) | WIRE_MAP) << 1) | 1);
            let len_pos = dst.len();
            dst.extend_from_slice(&[0, 0, WIRE_UINT, WIRE_SUB_MSG]);
            append_varint(dst, self.children.len() as u64);
            for (&k, child) in &self.children {
                append_varint(dst, u64::from(k));
                let c_len_pos = dst.len();
                dst.extend_from_slice(&[0, 0]);
                child.append_body(dst);
                backpatch_container_len(dst, c_len_pos);
            }
            backpatch_container_len(dst, len_pos);
        }
    }

    /// Merges `next` into `self` (later fields and children override or extend earlier ones).
    pub fn merge_from(&mut self, next: SchemaMeta) {
        if !next.type_name.is_empty() {
            self.type_name = next.type_name;
        }
        for (k, v) in next.fields {
            self.fields.insert(k, v);
        }
        for (k, child) in next.children {
            if let Some(existing) = self.children.get_mut(&k) {
                existing.merge_from(child);
            } else {
                self.children.insert(k, child);
            }
        }
    }
}

/// Merges two optional `SchemaMeta` definitions.
pub fn merge_schema_meta(base: Option<SchemaMeta>, next: SchemaMeta) -> SchemaMeta {
    match base {
        None => next,
        Some(mut existing) => {
            existing.merge_from(next);
            existing
        }
    }
}

const SCHEMA_FIELD_ENTRY_OVERHEAD: usize = 64;
const SCHEMA_CHILD_ENTRY_OVERHEAD: usize = 96;

#[inline]
fn charge_schema_alloc(rem_alloc: &mut usize, bytes: usize) -> Result<()> {
    if *rem_alloc == usize::MAX {
        return Ok(());
    }
    if bytes > *rem_alloc {
        return Err(Error::parse(
            "Field #0 SchemaMeta exceeds max_alloc_bytes budget",
        ));
    }
    *rem_alloc -= bytes;
    Ok(())
}

/// Validates a `SchemaMeta` payload slice in place with zero heap allocations,
/// returning the estimated heap bytes required to materialize the decoded tree.
pub(crate) fn validate_schema_meta_slice(
    data: &[u8],
    depth: usize,
    max_depth: usize,
) -> Result<usize> {
    if depth > max_depth {
        return Err(Error::DepthLimitExceeded(depth));
    }
    let mut est_alloc = 0usize;
    let mut pos = 0usize;
    let n = data.len();

    while pos < n {
        let (tag, tn) = decode_varint(&data[pos..]).ok_or_else(|| {
            Error::parse(format!(
                "truncated or invalid tag in Field #0 SchemaMeta at {pos}"
            ))
        })?;
        if (tag >> 4) > MAX_FIELD_NUMBER {
            return Err(Error::parse("invalid tag field number in SchemaMeta"));
        }
        pos += tn;
        let fnum = tag >> 4;
        let wt = (tag & 0x0F) as u8;

        match fnum {
            1 => {
                if wt != WIRE_STRING {
                    return Err(Error::parse(format!(
                        "SchemaMeta field #1 (type_name) must be WireString, got {wt}"
                    )));
                }
                let (s, next_pos) = read_str_slice(data, pos)?;
                est_alloc = est_alloc.saturating_add(s.len());
                pos = next_pos;
            }
            2 => {
                if wt != WIRE_MAP {
                    return Err(Error::parse(format!(
                        "SchemaMeta field #2 (fields) must be WireMap, got {wt}"
                    )));
                }
                if depth + 1 > max_depth {
                    return Err(Error::DepthLimitExceeded(depth + 1));
                }
                let (body, next_pos) = read_len_slice(data, pos, 3)?;
                pos = next_pos;
                let (key_wt, val_wt, count, mut p) = parse_map_header(body)
                    .ok_or_else(|| Error::parse("invalid SchemaMeta fields map header"))?;
                if key_wt != WIRE_UINT || val_wt != WIRE_STRING {
                    return Err(Error::parse("invalid SchemaMeta fields map key/val types"));
                }
                est_alloc =
                    est_alloc.saturating_add(count.saturating_mul(SCHEMA_FIELD_ENTRY_OVERHEAD));
                for _ in 0..count {
                    let (k64, kn) = decode_varint(&body[p..]).ok_or_else(|| {
                        Error::parse(format!("truncated SchemaMeta field key at {p}"))
                    })?;
                    if k64 == 0 || k64 > MAX_FIELD_NUMBER {
                        return Err(Error::parse(format!(
                            "invalid SchemaMeta field number {k64} at {p}"
                        )));
                    }
                    p += kn;
                    let (name, next_p) = read_str_slice(body, p)?;
                    est_alloc = est_alloc.saturating_add(name.len());
                    p = next_p;
                }
                if p != body.len() {
                    return Err(Error::parse("SchemaMeta fields map trailing bytes"));
                }
            }
            3 => {
                if wt != WIRE_MAP {
                    return Err(Error::parse(format!(
                        "SchemaMeta field #3 (children) must be WireMap, got {wt}"
                    )));
                }
                if depth + 1 > max_depth {
                    return Err(Error::DepthLimitExceeded(depth + 1));
                }
                let (body, next_pos) = read_len_slice(data, pos, 3)?;
                pos = next_pos;
                let (key_wt, val_wt, count, mut p) = parse_map_header(body)
                    .ok_or_else(|| Error::parse("invalid SchemaMeta children map header"))?;
                if key_wt != WIRE_UINT || val_wt != WIRE_SUB_MSG {
                    return Err(Error::parse(
                        "invalid SchemaMeta children map key/val types",
                    ));
                }
                est_alloc =
                    est_alloc.saturating_add(count.saturating_mul(SCHEMA_CHILD_ENTRY_OVERHEAD));
                for _ in 0..count {
                    let (k64, kn) = decode_varint(&body[p..]).ok_or_else(|| {
                        Error::parse(format!("truncated SchemaMeta child key at {p}"))
                    })?;
                    if k64 == 0 || k64 > MAX_FIELD_NUMBER {
                        return Err(Error::parse(format!(
                            "invalid SchemaMeta child field number {k64} at {p}"
                        )));
                    }
                    p += kn;
                    let (child_bytes, next_p) = read_len_slice(body, p, 0)?;
                    let child_est = validate_schema_meta_slice(child_bytes, depth + 2, max_depth)?;
                    est_alloc = est_alloc.saturating_add(child_est);
                    p = next_p;
                }
                if p != body.len() {
                    return Err(Error::parse("SchemaMeta children map trailing bytes"));
                }
            }
            0 => {
                return Err(Error::parse("invalid field #0 inside SchemaMeta"));
            }
            _ => {
                pos = validate_value_with_max_depth(data, pos, wt, depth, max_depth)?;
            }
        }
    }
    Ok(est_alloc)
}

/// Decodes a `SchemaMeta` payload body at the given recursion `depth`.
pub fn decode_schema_meta(data: &[u8], depth: usize) -> Result<SchemaMeta> {
    decode_schema_meta_with_max_depth(data, depth, MAX_NESTING_DEPTH)
}

/// Decodes a `SchemaMeta` payload body enforcing `max_depth`.
pub(crate) fn decode_schema_meta_with_max_depth(
    data: &[u8],
    depth: usize,
    max_depth: usize,
) -> Result<SchemaMeta> {
    let mut unlimited = usize::MAX;
    decode_schema_meta_with_budget(data, depth, max_depth, &mut unlimited)
}

/// Decodes a `SchemaMeta` payload body enforcing both `max_depth` and `rem_alloc` heap budget.
pub(crate) fn decode_schema_meta_with_budget(
    data: &[u8],
    depth: usize,
    max_depth: usize,
    rem_alloc: &mut usize,
) -> Result<SchemaMeta> {
    if depth > max_depth {
        return Err(Error::DepthLimitExceeded(depth));
    }
    let mut meta = SchemaMeta::default();
    let mut pos = 0usize;
    let n = data.len();

    while pos < n {
        let (tag, tn) = decode_varint(&data[pos..]).ok_or_else(|| {
            Error::parse(format!(
                "truncated or invalid tag in Field #0 SchemaMeta at {pos}"
            ))
        })?;
        if (tag >> 4) > MAX_FIELD_NUMBER {
            return Err(Error::parse("invalid tag field number in SchemaMeta"));
        }
        pos += tn;
        let fnum = tag >> 4;
        let wt = (tag & 0x0F) as u8;

        match fnum {
            1 => {
                if wt != WIRE_STRING {
                    return Err(Error::parse(format!(
                        "SchemaMeta field #1 (type_name) must be WireString, got {wt}"
                    )));
                }
                let (s, next_pos) = read_str_slice(data, pos)?;
                charge_schema_alloc(rem_alloc, s.len())?;
                meta.type_name = s.to_owned();
                pos = next_pos;
            }
            2 => {
                if wt != WIRE_MAP {
                    return Err(Error::parse(format!(
                        "SchemaMeta field #2 (fields) must be WireMap, got {wt}"
                    )));
                }
                if depth + 1 > max_depth {
                    return Err(Error::DepthLimitExceeded(depth + 1));
                }
                let (body, next_pos) = read_len_slice(data, pos, 3)?;
                pos = next_pos;
                let (key_wt, val_wt, count, mut p) = parse_map_header(body)
                    .ok_or_else(|| Error::parse("invalid SchemaMeta fields map header"))?;
                if key_wt != WIRE_UINT || val_wt != WIRE_STRING {
                    return Err(Error::parse("invalid SchemaMeta fields map key/val types"));
                }
                charge_schema_alloc(rem_alloc, count.saturating_mul(SCHEMA_FIELD_ENTRY_OVERHEAD))?;
                for _ in 0..count {
                    let (k64, kn) = decode_varint(&body[p..]).ok_or_else(|| {
                        Error::parse(format!("truncated SchemaMeta field key at {p}"))
                    })?;
                    if k64 == 0 || k64 > MAX_FIELD_NUMBER {
                        return Err(Error::parse(format!(
                            "invalid SchemaMeta field number {k64} at {p}"
                        )));
                    }
                    p += kn;
                    let (name, next_p) = read_str_slice(body, p)?;
                    charge_schema_alloc(rem_alloc, name.len())?;
                    meta.fields.insert(k64 as u32, name.to_owned());
                    p = next_p;
                }
                if p != body.len() {
                    return Err(Error::parse("SchemaMeta fields map trailing bytes"));
                }
            }
            3 => {
                if wt != WIRE_MAP {
                    return Err(Error::parse(format!(
                        "SchemaMeta field #3 (children) must be WireMap, got {wt}"
                    )));
                }
                if depth + 1 > max_depth {
                    return Err(Error::DepthLimitExceeded(depth + 1));
                }
                let (body, next_pos) = read_len_slice(data, pos, 3)?;
                pos = next_pos;
                let (key_wt, val_wt, count, mut p) = parse_map_header(body)
                    .ok_or_else(|| Error::parse("invalid SchemaMeta children map header"))?;
                if key_wt != WIRE_UINT || val_wt != WIRE_SUB_MSG {
                    return Err(Error::parse(
                        "invalid SchemaMeta children map key/val types",
                    ));
                }
                charge_schema_alloc(rem_alloc, count.saturating_mul(SCHEMA_CHILD_ENTRY_OVERHEAD))?;
                // Within a single WireMap container, duplicate keys replace outright (Spec §6.6).
                // Separate field #3 occurrences or separate Field #0 blocks merge recursively (Spec §8.2).
                let mut map_children: BTreeMap<u32, SchemaMeta> = BTreeMap::new();
                for _ in 0..count {
                    let (k64, kn) = decode_varint(&body[p..]).ok_or_else(|| {
                        Error::parse(format!("truncated SchemaMeta child key at {p}"))
                    })?;
                    if k64 == 0 || k64 > MAX_FIELD_NUMBER {
                        return Err(Error::parse(format!(
                            "invalid SchemaMeta child field number {k64} at {p}"
                        )));
                    }
                    p += kn;
                    let (child_bytes, next_p) = read_len_slice(body, p, 0)?;
                    let child_meta = decode_schema_meta_with_budget(
                        child_bytes,
                        depth + 2,
                        max_depth,
                        rem_alloc,
                    )?;
                    map_children.insert(k64 as u32, child_meta);
                    p = next_p;
                }
                if p != body.len() {
                    return Err(Error::parse("SchemaMeta children map trailing bytes"));
                }
                for (key, child_meta) in map_children {
                    if let Some(existing) = meta.children.get_mut(&key) {
                        existing.merge_from(child_meta);
                    } else {
                        meta.children.insert(key, child_meta);
                    }
                }
            }
            0 => {
                return Err(Error::parse("invalid field #0 inside SchemaMeta"));
            }
            _ => {
                pos = validate_value_with_max_depth(data, pos, wt, depth, max_depth)?;
            }
        }
    }
    Ok(meta)
}

/// Validates a `Field #0` (`WireSubMsg`) payload starting at `data[pos]` in place without heap allocation.
#[inline]
pub fn validate_field0(data: &[u8], pos: usize, depth: usize) -> Result<usize> {
    validate_field0_with_max_depth(data, pos, depth, MAX_NESTING_DEPTH)
}

/// Validates a `Field #0` (`WireSubMsg`) payload starting at `data[pos]` with custom `max_depth` and zero heap allocations.
#[inline]
pub(crate) fn validate_field0_with_max_depth(
    data: &[u8],
    pos: usize,
    depth: usize,
    max_depth: usize,
) -> Result<usize> {
    let (body, next_pos) = read_len_slice(data, pos, 0)?;
    validate_schema_meta_slice(body, depth + 1, max_depth)?;
    Ok(next_pos)
}

/// Validates a `Field #0` (`WireSubMsg`) payload starting at `data[pos]`, returning `(next_pos, estimated_alloc_bytes)`.
#[inline]
pub(crate) fn validate_field0_with_alloc(
    data: &[u8],
    pos: usize,
    depth: usize,
    max_depth: usize,
) -> Result<(usize, usize)> {
    let (body, next_pos) = read_len_slice(data, pos, 0)?;
    let est = validate_schema_meta_slice(body, depth + 1, max_depth)?;
    Ok((next_pos, est))
}

/// Decodes and merges all `Field #0` (`Tag = 0x19`, `WireSubMsg = 12`) blocks in `packet`.
pub fn read_field0_schema_meta(packet: &[u8]) -> Option<SchemaMeta> {
    read_field0_schema_meta_at_depth(packet, 0, MAX_NESTING_DEPTH)
        .ok()
        .flatten()
}

/// Decodes and merges all `Field #0` blocks in `packet` starting from `base_depth`.
pub(crate) fn read_field0_schema_meta_at_depth(
    packet: &[u8],
    base_depth: usize,
    max_depth: usize,
) -> Result<Option<SchemaMeta>> {
    let mut merged: Option<SchemaMeta> = None;
    let mut pos = 0usize;
    let n = packet.len();
    while pos < n {
        let (fnum, wt, after_tag) =
            read_tag_at(packet, pos).ok_or_else(|| Error::parse("invalid tag"))?;
        pos = after_tag;
        if fnum == 0 {
            if wt != WIRE_SUB_MSG {
                return Err(Error::parse(format!("invalid Field #0 wire type {wt}")));
            }
            let (body, end) = read_len_slice(packet, pos, 0)?;
            let meta = decode_schema_meta_with_max_depth(body, base_depth + 1, max_depth)?;
            merged = Some(merge_schema_meta(merged, meta));
            pos = end;
        } else {
            pos = skip_value_opt(packet, pos, wt)
                .ok_or_else(|| Error::parse("truncated field value"))?;
        }
    }
    Ok(merged)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_children_keys_within_single_wire_map_replace_while_separate_maps_merge() {
        let mut child_a = SchemaMeta {
            type_name: "OldChild".to_owned(),
            ..Default::default()
        };
        child_a.fields.insert(1, "old_only".to_owned());
        child_a.fields.insert(2, "shared".to_owned());

        let mut child_b = SchemaMeta {
            type_name: "NewChild".to_owned(),
            ..Default::default()
        };
        child_b.fields.insert(2, "updated".to_owned());

        // Hand-craft a single Field #3 WireMap containing duplicate key `5` -> child_a then `5` -> child_b.
        let mut child_a_body = Vec::new();
        child_a.append_body(&mut child_a_body);
        let mut child_b_body = Vec::new();
        child_b.append_body(&mut child_b_body);

        let mut schema_body = Vec::new();
        schema_body.push((((3 << 4) | WIRE_MAP) << 1) | 1);
        let map_pos = schema_body.len();
        schema_body.extend_from_slice(&[0, 0, WIRE_UINT, WIRE_SUB_MSG]);
        append_varint(&mut schema_body, 2); // 2 entries with same key 5
        append_varint(&mut schema_body, 5);
        append_varint(&mut schema_body, child_a_body.len() as u64);
        schema_body.extend_from_slice(&child_a_body);
        append_varint(&mut schema_body, 5);
        append_varint(&mut schema_body, child_b_body.len() as u64);
        schema_body.extend_from_slice(&child_b_body);
        backpatch_container_len(&mut schema_body, map_pos);

        let mut pkt = Vec::new();
        pkt.push((WIRE_SUB_MSG << 1) | 1);
        append_varint(&mut pkt, schema_body.len() as u64);
        pkt.extend_from_slice(&schema_body);

        let decoded = read_field0_schema_meta(&pkt).expect("valid Field #0");
        let child5 = decoded.children.get(&5).expect("child 5");
        assert_eq!(child5.type_name, "NewChild");
        // `old_only` must NOT survive because duplicate key 5 in the same WireMap replaces outright.
        assert!(!child5.fields.contains_key(&1));
        assert_eq!(child5.fields.get(&2).map(String::as_str), Some("updated"));

        // Now append a SEPARATE Field #0 block adding field 3 on child 5 -> must merge recursively.
        let mut ext_child = SchemaMeta::default();
        ext_child.fields.insert(3, "merged_extra".to_owned());
        let mut ext_root = SchemaMeta::default();
        ext_root.children.insert(5, ext_child);
        ext_root.append_field0(&mut pkt);

        let merged = read_field0_schema_meta(&pkt).expect("valid merged Field #0");
        let merged5 = merged.children.get(&5).expect("child 5");
        assert_eq!(merged5.type_name, "NewChild");
        assert!(!merged5.fields.contains_key(&1));
        assert_eq!(merged5.fields.get(&2).map(String::as_str), Some("updated"));
        assert_eq!(
            merged5.fields.get(&3).map(String::as_str),
            Some("merged_extra")
        );
    }
}
