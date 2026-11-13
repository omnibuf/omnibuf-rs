use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::wire::{
    MAX_FIELD_NUMBER, MAX_NESTING_DEPTH, WIRE_MAP, WIRE_STRING, WIRE_SUB_MSG, WIRE_UINT,
    append_varint, backpatch_container_len, decode_varint, next_container_field, parse_map_header,
    read_len_slice, read_str_slice, validate_value,
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

/// Decodes a `SchemaMeta` payload body at the given recursion `depth`.
pub fn decode_schema_meta(data: &[u8], depth: usize) -> Result<SchemaMeta> {
    if depth > MAX_NESTING_DEPTH {
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
                meta.type_name = s.to_owned();
                pos = next_pos;
            }
            2 => {
                if wt != WIRE_MAP {
                    return Err(Error::parse(format!(
                        "SchemaMeta field #2 (fields) must be WireMap, got {wt}"
                    )));
                }
                if depth + 1 > MAX_NESTING_DEPTH {
                    return Err(Error::DepthLimitExceeded(depth + 1));
                }
                let (body, next_pos) = read_len_slice(data, pos, 3)?;
                pos = next_pos;
                let (key_wt, val_wt, count, mut p) = parse_map_header(body)
                    .ok_or_else(|| Error::parse("invalid SchemaMeta fields map header"))?;
                if key_wt != WIRE_UINT || val_wt != WIRE_STRING {
                    return Err(Error::parse("invalid SchemaMeta fields map key/val types"));
                }
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
                if depth + 1 > MAX_NESTING_DEPTH {
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
                    let child_meta = decode_schema_meta(child_bytes, depth + 1)?;
                    let key = k64 as u32;
                    if let Some(existing) = meta.children.get_mut(&key) {
                        existing.merge_from(child_meta);
                    } else {
                        meta.children.insert(key, child_meta);
                    }
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
                pos = validate_value(data, pos, wt, depth)?;
            }
        }
    }
    Ok(meta)
}

/// Validates a `Field #0` (`WireSubMsg`) payload starting at `data[pos]` in place.
#[inline]
pub fn validate_field0(data: &[u8], pos: usize, depth: usize) -> Result<usize> {
    let (body, next_pos) = read_len_slice(data, pos, 0)?;
    decode_schema_meta(body, depth + 1)?;
    Ok(next_pos)
}

/// Decodes and merges all `Field #0` (`Tag = 0x19`, `WireSubMsg = 12`) blocks in `packet`.
pub fn read_field0_schema_meta(packet: &[u8]) -> Option<SchemaMeta> {
    let mut merged: Option<SchemaMeta> = None;
    let mut pos = 0usize;
    loop {
        let (matched, valid) = next_container_field(packet, pos, 0, WIRE_SUB_MSG, 0, true);
        if !valid {
            return None;
        }
        let Some((body, next_pos)) = matched else {
            return merged;
        };
        pos = next_pos;
        let meta = decode_schema_meta(body, 0).ok()?;
        merged = Some(merge_schema_meta(merged, meta));
    }
}
