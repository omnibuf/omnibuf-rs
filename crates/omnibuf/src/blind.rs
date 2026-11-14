use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};

use crate::error::{Error, Result};
use crate::field0::{
    SchemaMeta, decode_schema_meta_with_max_depth, merge_schema_meta,
    validate_field0_with_max_depth,
};
use crate::message::DecodeOptions;
use crate::wire::{
    MAX_FIELD_NUMBER, MAX_NESTING_DEPTH, WIRE_ARRAY, WIRE_BOOL_FALSE, WIRE_BOOL_TRUE, WIRE_BYTES,
    WIRE_EXTENDED, WIRE_FIXED32, WIRE_FIXED64, WIRE_FLOAT32, WIRE_FLOAT64, WIRE_MAP, WIRE_SFIXED32,
    WIRE_SFIXED64, WIRE_SINT, WIRE_STRING, WIRE_SUB_MSG, WIRE_UINT, decode_varint, decode_zigzag,
    fast_skip_value, parse_array_header, parse_map_header, read_len_slice, read_str_slice,
    validate_value,
};

/// Dynamic value returned by schema-less [`decode_blind`] packet inspection.
#[derive(Clone, Debug, PartialEq)]
pub enum BlindValue {
    Bool(bool),
    Uint(u64),
    Int(i64),
    Float32(f32),
    Float64(f64),
    String(String),
    Bytes(Vec<u8>),
    Array(Vec<BlindValue>),
    Object(BTreeMap<String, BlindValue>),
}

/// Options controlling [`decode_blind_with_options`].
#[derive(Clone, Debug)]
pub struct DecodeBlindOptions<'a> {
    /// Optional pre-decoded `SchemaMeta` inherited before any local `Field #0` blocks.
    pub inherited_schema: Option<&'a SchemaMeta>,
    /// Maximum allowed input packet byte length (`default = 64 MiB`).
    pub max_message_bytes: usize,
    /// Maximum cumulative container element count across arrays and maps (`default = 4,194,304`).
    pub max_elements: usize,
    /// Maximum cumulative allocation budget (`default = 64 MiB`).
    pub max_alloc_bytes: usize,
    /// Maximum allowed container and sub-message recursion depth (`default = MAX_NESTING_DEPTH = 32`).
    pub max_depth: usize,
}

impl Default for DecodeBlindOptions<'_> {
    #[inline]
    fn default() -> Self {
        let base = DecodeOptions::default_limits();
        Self {
            inherited_schema: None,
            max_message_bytes: base.max_message_bytes,
            max_elements: base.max_elements,
            max_alloc_bytes: base.max_alloc_bytes,
            max_depth: base.max_depth,
        }
    }
}

struct BlindBudget {
    max_elements: usize,
    max_alloc_bytes: usize,
    max_depth: usize,
    elements: usize,
    alloc_bytes: usize,
}

impl BlindBudget {
    fn from_options(opts: &DecodeBlindOptions<'_>) -> Self {
        Self {
            max_elements: opts.max_elements,
            max_alloc_bytes: opts.max_alloc_bytes,
            max_depth: opts.max_depth.min(MAX_NESTING_DEPTH),
            elements: 0,
            alloc_bytes: 0,
        }
    }

    #[inline]
    fn add_elements(&mut self, count: usize) -> Result<()> {
        self.elements = self
            .elements
            .checked_add(count)
            .ok_or_else(|| Error::parse("element count budget overflow"))?;
        if self.elements > self.max_elements {
            return Err(Error::parse(format!(
                "container element count {} exceeds max_elements {}",
                self.elements, self.max_elements
            )));
        }
        Ok(())
    }

    #[inline]
    fn add_alloc(&mut self, bytes: usize) -> Result<()> {
        self.alloc_bytes = self
            .alloc_bytes
            .checked_add(bytes)
            .ok_or_else(|| Error::parse("allocation budget overflow"))?;
        if self.alloc_bytes > self.max_alloc_bytes {
            return Err(Error::parse(format!(
                "allocation budget {} exceeds max_alloc_bytes {}",
                self.alloc_bytes, self.max_alloc_bytes
            )));
        }
        Ok(())
    }
}

const BASE64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes `bytes` as a standard RFC 4648 Base64 string.
pub fn encode_base64(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut i = 0usize;
    while i + 2 < bytes.len() {
        let n =
            (u32::from(bytes[i]) << 16) | (u32::from(bytes[i + 1]) << 8) | u32::from(bytes[i + 2]);
        out.push(BASE64_CHARS[((n >> 18) & 63) as usize] as char);
        out.push(BASE64_CHARS[((n >> 12) & 63) as usize] as char);
        out.push(BASE64_CHARS[((n >> 6) & 63) as usize] as char);
        out.push(BASE64_CHARS[(n & 63) as usize] as char);
        i += 3;
    }
    let rem = bytes.len() - i;
    if rem == 1 {
        let n = u32::from(bytes[i]) << 16;
        out.push(BASE64_CHARS[((n >> 18) & 63) as usize] as char);
        out.push(BASE64_CHARS[((n >> 12) & 63) as usize] as char);
        out.push_str("==");
    } else if rem == 2 {
        let n = (u32::from(bytes[i]) << 16) | (u32::from(bytes[i + 1]) << 8);
        out.push(BASE64_CHARS[((n >> 18) & 63) as usize] as char);
        out.push(BASE64_CHARS[((n >> 12) & 63) as usize] as char);
        out.push(BASE64_CHARS[((n >> 6) & 63) as usize] as char);
        out.push('=');
    }
    out
}

/// Overlay chain of `SchemaMeta` layers bounded by `MAX_NESTING_DEPTH` so shared schemas
/// are never deep-cloned across repeated sub-message elements.
#[derive(Clone, Copy)]
struct BlindSchema<'a> {
    local: &'a SchemaMeta,
    parent: Option<&'a BlindSchema<'a>>,
}

impl<'a> BlindSchema<'a> {
    fn field_name(&self, field: u32) -> &str {
        let mut cur = Some(self);
        while let Some(layer) = cur {
            if let Some(name) = layer.local.fields.get(&field) {
                return name.as_str();
            }
            cur = layer.parent;
        }
        ""
    }
}

/// Collects child `SchemaMeta` layers from outermost to innermost without cloning `SchemaMeta`.
fn resolve_child_layers<'a>(
    schema: Option<&'a BlindSchema<'a>>,
    field: u32,
    out: &mut Vec<&'a SchemaMeta>,
) {
    let Some(s) = schema else {
        return;
    };
    resolve_child_layers(s.parent, field, out);
    if let Some(child) = s.local.children.get(&field) {
        out.push(child);
    }
}

fn decode_with_layers(
    data: &[u8],
    layers: &[&SchemaMeta],
    depth: usize,
    budget: &mut BlindBudget,
) -> Result<BTreeMap<String, BlindValue>> {
    fn invoke<'a>(
        data: &[u8],
        rest: &[&'a SchemaMeta],
        parent: Option<&'a BlindSchema<'a>>,
        depth: usize,
        budget: &mut BlindBudget,
    ) -> Result<BTreeMap<String, BlindValue>> {
        if let Some((&first, tail)) = rest.split_first() {
            let node = BlindSchema {
                local: first,
                parent,
            };
            invoke(data, tail, Some(&node), depth, budget)
        } else {
            decode_blind_inner(data, parent, depth, budget)
        }
    }
    invoke(data, layers, None, depth, budget)
}

/// Decodes any OmniBuf packet without a compile-time schema.
///
/// When `Field #0` (`omnibuf.v1.SchemaMeta`) is present, declared field names are resolved
/// across nested sub-messages, sub-message arrays, and map values. Absent names fall back
/// to `"field_<N>"`.
pub fn decode_blind(packet: &[u8]) -> Result<BTreeMap<String, BlindValue>> {
    decode_blind_with_options(packet, DecodeBlindOptions::default())
}

/// Decodes any OmniBuf packet without a compile-time schema using explicit [`DecodeBlindOptions`].
pub fn decode_blind_with_options(
    packet: &[u8],
    options: DecodeBlindOptions<'_>,
) -> Result<BTreeMap<String, BlindValue>> {
    if packet.len() > options.max_message_bytes {
        return Err(Error::parse(format!(
            "message length {} exceeds max_message_bytes {}",
            packet.len(),
            options.max_message_bytes
        )));
    }
    let mut budget = BlindBudget::from_options(&options);
    if let Some(inherited) = options.inherited_schema {
        let root = BlindSchema {
            local: inherited,
            parent: None,
        };
        decode_blind_inner(packet, Some(&root), 0, &mut budget)
    } else {
        decode_blind_inner(packet, None, 0, &mut budget)
    }
}

#[derive(Clone, Debug)]
struct BlindShape {
    wt: u8,
    key_wt: u8,
    any_map: bool,
    elem: Option<Box<BlindShape>>,
}

fn unify_blind_shapes(a: Option<&BlindShape>, b: Option<&BlindShape>) -> Option<BlindShape> {
    let Some(sa) = a else {
        return b.cloned();
    };
    let Some(sb) = b else {
        return Some(sa.clone());
    };
    if sa.wt != sb.wt {
        return None;
    }
    if sa.wt == WIRE_MAP {
        if sa.any_map {
            return Some(sb.clone());
        }
        if sb.any_map {
            return Some(sa.clone());
        }
        if sa.key_wt != sb.key_wt {
            return None;
        }
    }
    if sa.wt != WIRE_ARRAY && sa.wt != WIRE_MAP {
        return Some(sa.clone());
    }
    let elem = match (sa.elem.as_deref(), sb.elem.as_deref()) {
        (None, None) => None,
        (sa_e, sb_e) => Some(Box::new(unify_blind_shapes(sa_e, sb_e)?)),
    };
    Some(BlindShape {
        wt: sa.wt,
        key_wt: sa.key_wt,
        any_map: false,
        elem,
    })
}

fn parse_blind_field_shape(
    data: &[u8],
    pos: usize,
    wt: u8,
    depth: usize,
    max_depth: usize,
) -> Result<BlindShape> {
    let norm_wt = if wt == WIRE_BOOL_TRUE {
        WIRE_BOOL_FALSE
    } else {
        wt
    };
    if norm_wt != WIRE_ARRAY && norm_wt != WIRE_MAP {
        return Ok(BlindShape {
            wt: norm_wt,
            key_wt: 0,
            any_map: false,
            elem: None,
        });
    }
    let (shape, _) = parse_blind_container_shape(data, pos, norm_wt, depth, max_depth)?;
    Ok(shape)
}

fn skip_blind_map_key(body: &[u8], p: usize, key_wt: u8) -> Result<usize> {
    match key_wt {
        WIRE_STRING => read_str_slice(body, p).map(|(_, next)| next),
        WIRE_UINT | WIRE_SINT => decode_varint(body.get(p..).unwrap_or(&[]))
            .map(|(_, vn)| p + vn)
            .ok_or_else(|| Error::parse(format!("truncated WireMap key at {p}"))),
        WIRE_FIXED32 | WIRE_SFIXED32 => {
            if body.len().saturating_sub(p) < 4 {
                return Err(Error::parse(format!(
                    "truncated WireMap fixed32 key at {p}"
                )));
            }
            Ok(p + 4)
        }
        WIRE_FIXED64 | WIRE_SFIXED64 => {
            if body.len().saturating_sub(p) < 8 {
                return Err(Error::parse(format!(
                    "truncated WireMap fixed64 key at {p}"
                )));
            }
            Ok(p + 8)
        }
        WIRE_BOOL_FALSE => {
            let b = *body
                .get(p)
                .ok_or_else(|| Error::parse(format!("truncated WireMap bool key at {p}")))?;
            if b > 1 {
                return Err(Error::parse(format!("invalid WireMap bool key {b} at {p}")));
            }
            Ok(p + 1)
        }
        _ => Err(Error::parse(format!(
            "invalid WireMap key wire type {key_wt}"
        ))),
    }
}

fn parse_blind_container_shape(
    data: &[u8],
    pos: usize,
    wt: u8,
    depth: usize,
    max_depth: usize,
) -> Result<(BlindShape, usize)> {
    if depth + 1 > max_depth {
        return Err(Error::DepthLimitExceeded(depth + 1));
    }
    if wt == WIRE_ARRAY {
        let (body, next_pos) = read_len_slice(data, pos, 2)?;
        let (elem_wt, count, mut p) =
            parse_array_header(body).ok_or_else(|| Error::parse("invalid WireArray header"))?;
        if elem_wt != WIRE_ARRAY && elem_wt != WIRE_MAP {
            return Ok((
                BlindShape {
                    wt: WIRE_ARRAY,
                    key_wt: 0,
                    any_map: false,
                    elem: Some(Box::new(BlindShape {
                        wt: elem_wt,
                        key_wt: 0,
                        any_map: false,
                        elem: None,
                    })),
                },
                next_pos,
            ));
        }
        if count == 0 {
            if p != body.len() {
                return Err(Error::parse("array count/length mismatch"));
            }
            let inner = if elem_wt == WIRE_ARRAY {
                BlindShape {
                    wt: WIRE_ARRAY,
                    key_wt: 0,
                    any_map: false,
                    elem: None,
                }
            } else {
                BlindShape {
                    wt: WIRE_MAP,
                    key_wt: 0,
                    any_map: true,
                    elem: None,
                }
            };
            return Ok((
                BlindShape {
                    wt: WIRE_ARRAY,
                    key_wt: 0,
                    any_map: false,
                    elem: Some(Box::new(inner)),
                },
                next_pos,
            ));
        }
        let mut merged: Option<BlindShape> = None;
        for _ in 0..count {
            let (elem_shape, next_p) =
                parse_blind_container_shape(body, p, elem_wt, depth + 1, max_depth)?;
            merged = Some(
                unify_blind_shapes(merged.as_ref(), Some(&elem_shape)).ok_or_else(|| {
                    Error::parse("inconsistent nested container element shapes in WireArray")
                })?,
            );
            p = next_p;
        }
        if p != body.len() {
            return Err(Error::parse("array count/length mismatch"));
        }
        return Ok((
            BlindShape {
                wt: WIRE_ARRAY,
                key_wt: 0,
                any_map: false,
                elem: merged.map(Box::new),
            },
            next_pos,
        ));
    }

    let (body, next_pos) = read_len_slice(data, pos, 3)?;
    let (key_wt, val_wt, count, mut p) =
        parse_map_header(body).ok_or_else(|| Error::parse("invalid WireMap header"))?;
    if val_wt != WIRE_ARRAY && val_wt != WIRE_MAP {
        return Ok((
            BlindShape {
                wt: WIRE_MAP,
                key_wt,
                any_map: false,
                elem: Some(Box::new(BlindShape {
                    wt: val_wt,
                    key_wt: 0,
                    any_map: false,
                    elem: None,
                })),
            },
            next_pos,
        ));
    }
    if count == 0 {
        if p != body.len() {
            return Err(Error::parse("WireMap trailing bytes"));
        }
        let inner = if val_wt == WIRE_ARRAY {
            BlindShape {
                wt: WIRE_ARRAY,
                key_wt: 0,
                any_map: false,
                elem: None,
            }
        } else {
            BlindShape {
                wt: WIRE_MAP,
                key_wt: 0,
                any_map: true,
                elem: None,
            }
        };
        return Ok((
            BlindShape {
                wt: WIRE_MAP,
                key_wt,
                any_map: false,
                elem: Some(Box::new(inner)),
            },
            next_pos,
        ));
    }
    let mut merged: Option<BlindShape> = None;
    for _ in 0..count {
        let after_k = skip_blind_map_key(body, p, key_wt)?;
        let (val_shape, next_p) =
            parse_blind_container_shape(body, after_k, val_wt, depth + 1, max_depth)?;
        merged = Some(
            unify_blind_shapes(merged.as_ref(), Some(&val_shape)).ok_or_else(|| {
                Error::parse("inconsistent nested container value shapes in WireMap")
            })?,
        );
        p = next_p;
    }
    if p != body.len() {
        return Err(Error::parse("WireMap trailing bytes"));
    }
    Ok((
        BlindShape {
            wt: WIRE_MAP,
            key_wt,
            any_map: false,
            elem: merged.map(Box::new),
        },
        next_pos,
    ))
}

fn validate_blind_message_slice(data: &[u8], depth: usize, max_depth: usize) -> Result<()> {
    if depth > max_depth {
        return Err(Error::DepthLimitExceeded(depth));
    }
    let mut pos = 0usize;
    let n = data.len();
    while pos < n {
        let (tag, tn) = decode_varint(&data[pos..])
            .ok_or_else(|| Error::parse(format!("invalid or truncated tag at {pos}")))?;
        if (tag >> 4) > MAX_FIELD_NUMBER {
            return Err(Error::parse(format!(
                "tag field number exceeds max at {pos}"
            )));
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
            pos = validate_value(data, pos, wt, depth)?;
        }
    }
    Ok(())
}

fn decode_blind_inner(
    data: &[u8],
    inherited: Option<&BlindSchema<'_>>,
    depth: usize,
    budget: &mut BlindBudget,
) -> Result<BTreeMap<String, BlindValue>> {
    if depth > budget.max_depth {
        return Err(Error::DepthLimitExceeded(depth));
    }
    let n = data.len();
    if n == 0 {
        return Ok(BTreeMap::new());
    }

    let mut local_schema: Option<SchemaMeta> = None;

    // Pass 1: Pre-scan all Field #0 blocks so trailing metadata renames earlier fields consistently.
    let mut scan = 0usize;
    while scan < n {
        let (tag, tn) = decode_varint(&data[scan..])
            .ok_or_else(|| Error::parse(format!("invalid tag at {scan}")))?;
        if (tag >> 4) > MAX_FIELD_NUMBER {
            return Err(Error::parse(format!(
                "tag field number exceeds max at {scan}"
            )));
        }
        scan += tn;
        let wt = (tag & 0x0F) as u8;
        if (tag >> 4) == 0 {
            if wt != WIRE_SUB_MSG {
                return Err(Error::parse(format!("invalid Field #0 wire type {wt}")));
            }
            let (body, next) = read_len_slice(data, scan, 0)?;
            budget.add_alloc(body.len())?;
            let meta = decode_schema_meta_with_max_depth(body, depth + 1, budget.max_depth)?;
            local_schema = Some(merge_schema_meta(local_schema, meta));
            scan = next;
        } else {
            scan = fast_skip_value(data, scan, wt)
                .ok_or_else(|| Error::parse(format!("invalid field payload at {scan}")))?;
        }
    }

    let active_node;
    let active_schema: Option<&BlindSchema<'_>> = if let Some(ref meta) = local_schema {
        active_node = BlindSchema {
            local: meta,
            parent: inherited,
        };
        Some(&active_node)
    } else {
        inherited
    };

    let mut out = BTreeMap::new();
    let mut sub_packets: BTreeMap<u32, (String, Cow<'_, [u8]>)> = BTreeMap::new();
    let mut shapes: HashMap<u32, BlindShape> = HashMap::new();
    let mut owners: HashMap<String, u32> = HashMap::new();
    let mut pos = 0usize;

    while pos < n {
        let (tag, tn) = decode_varint(&data[pos..])
            .ok_or_else(|| Error::parse(format!("truncated tag at {pos}")))?;
        pos += tn;
        let field_num = (tag >> 4) as u32;
        let wt = (tag & 0x0F) as u8;

        if field_num == 0 {
            let (_, next_pos) = read_len_slice(data, pos, 0)?;
            pos = next_pos;
            continue;
        }

        let resolved = active_schema.map_or("", |s| s.field_name(field_num));
        let name = if resolved.is_empty() {
            format!("field_{field_num}")
        } else {
            resolved.to_owned()
        };

        if let Some(&owner) = owners.get(&name)
            && owner != field_num
        {
            return Err(Error::parse(format!(
                "fields #{owner} and #{field_num} both decode to name {name:?}"
            )));
        }
        owners.insert(name.clone(), field_num);

        let mut shape = parse_blind_field_shape(data, pos, wt, depth, budget.max_depth)?;
        if let Some(prev_shape) = shapes.get(&field_num) {
            shape = unify_blind_shapes(Some(prev_shape), Some(&shape)).ok_or_else(|| {
                Error::parse(format!(
                    "field #{field_num} changes wire shape within one message"
                ))
            })?;
        }
        shapes.insert(field_num, shape);

        match wt {
            WIRE_UINT => {
                let (v, vn) = decode_varint(&data[pos..])
                    .ok_or_else(|| Error::parse(format!("truncated WireUint at {pos}")))?;
                pos += vn;
                out.insert(name, BlindValue::Uint(v));
            }
            WIRE_SINT => {
                let (v, vn) = decode_varint(&data[pos..])
                    .ok_or_else(|| Error::parse(format!("truncated WireSint at {pos}")))?;
                pos += vn;
                out.insert(name, BlindValue::Int(decode_zigzag(v)));
            }
            WIRE_BOOL_FALSE => {
                out.insert(name, BlindValue::Bool(false));
            }
            WIRE_BOOL_TRUE => {
                out.insert(name, BlindValue::Bool(true));
            }
            WIRE_STRING => {
                let (s, next_pos) = read_str_slice(data, pos)?;
                budget.add_alloc(s.len())?;
                out.insert(name, BlindValue::String(s.to_owned()));
                pos = next_pos;
            }
            WIRE_BYTES => {
                let (b, next_pos) = read_len_slice(data, pos, 0)?;
                budget.add_alloc(b.len())?;
                out.insert(name, BlindValue::Bytes(b.to_vec()));
                pos = next_pos;
            }
            WIRE_SUB_MSG => {
                let (sub_bytes, next_pos) = read_len_slice(data, pos, 0)?;
                match sub_packets.get_mut(&field_num) {
                    Some((_, existing)) => {
                        if matches!(existing, Cow::Borrowed(_)) {
                            validate_blind_message_slice(existing, depth + 1, budget.max_depth)?;
                        }
                        validate_blind_message_slice(sub_bytes, depth + 1, budget.max_depth)?;
                        budget.add_alloc(sub_bytes.len())?;
                        existing.to_mut().extend_from_slice(sub_bytes);
                    }
                    None => {
                        sub_packets.insert(field_num, (name, Cow::Borrowed(sub_bytes)));
                    }
                }
                pos = next_pos;
            }
            WIRE_ARRAY => {
                let (body, next_pos) = read_len_slice(data, pos, 2)?;
                let mut child_layers = Vec::new();
                resolve_child_layers(active_schema, field_num, &mut child_layers);
                let mut arr = match out.remove(&name) {
                    Some(BlindValue::Array(existing)) => existing,
                    _ => Vec::new(),
                };
                decode_array_blind(&mut arr, body, &child_layers, depth + 1, budget)?;
                out.insert(name, BlindValue::Array(arr));
                pos = next_pos;
            }
            WIRE_EXTENDED => {
                let _ = read_len_slice(data, pos, 1)?;
                return Err(Error::parse("unknown extension"));
            }
            WIRE_MAP => {
                if depth + 1 > budget.max_depth {
                    return Err(Error::DepthLimitExceeded(depth + 1));
                }
                let (body, next_pos) = read_len_slice(data, pos, 3)?;
                let mut child_layers = Vec::new();
                resolve_child_layers(active_schema, field_num, &mut child_layers);
                let mut map = match out.remove(&name) {
                    Some(BlindValue::Object(existing)) => existing,
                    _ => BTreeMap::new(),
                };
                decode_map_body_blind(&mut map, body, &child_layers, depth + 1, budget)?;
                out.insert(name, BlindValue::Object(map));
                pos = next_pos;
            }
            WIRE_FIXED32 | WIRE_FLOAT32 | WIRE_SFIXED32 => {
                let raw: [u8; 4] = data
                    .get(pos..pos + 4)
                    .ok_or_else(|| Error::parse(format!("truncated 32-bit scalar at {pos}")))?
                    .try_into()
                    .unwrap();
                let bits = u32::from_le_bytes(raw);
                let val = match wt {
                    WIRE_FLOAT32 => BlindValue::Float32(f32::from_bits(bits)),
                    WIRE_SFIXED32 => BlindValue::Int(i64::from(bits as i32)),
                    _ => BlindValue::Uint(u64::from(bits)),
                };
                out.insert(name, val);
                pos += 4;
            }
            WIRE_FIXED64 | WIRE_FLOAT64 | WIRE_SFIXED64 => {
                let raw: [u8; 8] = data
                    .get(pos..pos + 8)
                    .ok_or_else(|| Error::parse(format!("truncated 64-bit scalar at {pos}")))?
                    .try_into()
                    .unwrap();
                let bits = u64::from_le_bytes(raw);
                let val = match wt {
                    WIRE_FLOAT64 => BlindValue::Float64(f64::from_bits(bits)),
                    WIRE_SFIXED64 => BlindValue::Int(bits as i64),
                    _ => BlindValue::Uint(bits),
                };
                out.insert(name, val);
                pos += 8;
            }
            _ => {
                return Err(Error::parse(format!("unsupported wire type {wt}")));
            }
        }
    }

    for (field_num, (name, packet)) in sub_packets {
        let mut child_layers = Vec::new();
        resolve_child_layers(active_schema, field_num, &mut child_layers);
        let child_obj = decode_with_layers(&packet, &child_layers, depth + 1, budget)?;
        out.insert(name, BlindValue::Object(child_obj));
    }

    Ok(out)
}

fn decode_array_blind(
    dst: &mut Vec<BlindValue>,
    body: &[u8],
    child_layers: &[&SchemaMeta],
    depth: usize,
    budget: &mut BlindBudget,
) -> Result<()> {
    if depth > budget.max_depth {
        return Err(Error::DepthLimitExceeded(depth));
    }
    let (elem, count, mut p) =
        parse_array_header(body).ok_or_else(|| Error::parse("invalid WireArray header"))?;
    budget.add_elements(count)?;
    budget.add_alloc(count.saturating_mul(core::mem::size_of::<BlindValue>()))?;
    dst.reserve(count.min(4096));

    for _ in 0..count {
        match elem {
            WIRE_ARRAY => {
                let (nested, next_p) = read_len_slice(body, p, 2)?;
                let mut inner = Vec::new();
                decode_array_blind(&mut inner, nested, child_layers, depth + 1, budget)?;
                dst.push(BlindValue::Array(inner));
                p = next_p;
            }
            WIRE_MAP => {
                let (nested, next_p) = read_len_slice(body, p, 3)?;
                let mut inner = BTreeMap::new();
                decode_map_body_blind(&mut inner, nested, child_layers, depth + 1, budget)?;
                dst.push(BlindValue::Object(inner));
                p = next_p;
            }
            _ => {
                let (val, next_p) =
                    decode_map_val_blind(body, p, elem, child_layers, depth, budget)?;
                dst.push(val);
                p = next_p;
            }
        }
    }

    if p != body.len() {
        return Err(Error::parse("array count/length mismatch"));
    }
    Ok(())
}

fn decode_map_body_blind(
    dst: &mut BTreeMap<String, BlindValue>,
    body: &[u8],
    child_layers: &[&SchemaMeta],
    depth: usize,
    budget: &mut BlindBudget,
) -> Result<()> {
    if depth > budget.max_depth {
        return Err(Error::DepthLimitExceeded(depth));
    }
    let (key_wt, val_wt, count, mut p) =
        parse_map_header(body).ok_or_else(|| Error::parse("invalid WireMap header"))?;
    budget.add_elements(count)?;
    budget.add_alloc(count.saturating_mul(core::mem::size_of::<(String, BlindValue)>()))?;

    for _ in 0..count {
        let (k, after_k) = decode_map_key_blind(body, p, key_wt, budget)?;
        let (v, after_v) =
            decode_map_val_blind(body, after_k, val_wt, child_layers, depth, budget)?;
        dst.insert(k, v);
        p = after_v;
    }

    if p != body.len() {
        return Err(Error::parse(format!(
            "WireMap trailing bytes (parsed {p}, body {})",
            body.len()
        )));
    }
    Ok(())
}

fn decode_map_key_blind(
    body: &[u8],
    p: usize,
    key_wt: u8,
    budget: &mut BlindBudget,
) -> Result<(String, usize)> {
    match key_wt {
        WIRE_STRING => {
            let (s, next_p) = read_str_slice(body, p)?;
            budget.add_alloc(s.len())?;
            Ok((s.to_owned(), next_p))
        }
        WIRE_UINT => {
            let (v, vn) = decode_varint(&body[p..])
                .ok_or_else(|| Error::parse(format!("truncated WireMap uint key at {p}")))?;
            Ok((v.to_string(), p + vn))
        }
        WIRE_SINT => {
            let (v, vn) = decode_varint(&body[p..])
                .ok_or_else(|| Error::parse(format!("truncated WireMap sint key at {p}")))?;
            Ok((decode_zigzag(v).to_string(), p + vn))
        }
        WIRE_FIXED32 | WIRE_SFIXED32 => {
            let raw: [u8; 4] = body
                .get(p..p + 4)
                .ok_or_else(|| Error::parse(format!("truncated WireMap fixed32 key at {p}")))?
                .try_into()
                .unwrap();
            let bits = u32::from_le_bytes(raw);
            let s = if key_wt == WIRE_SFIXED32 {
                (bits as i32).to_string()
            } else {
                bits.to_string()
            };
            Ok((s, p + 4))
        }
        WIRE_FIXED64 | WIRE_SFIXED64 => {
            let raw: [u8; 8] = body
                .get(p..p + 8)
                .ok_or_else(|| Error::parse(format!("truncated WireMap fixed64 key at {p}")))?
                .try_into()
                .unwrap();
            let bits = u64::from_le_bytes(raw);
            let s = if key_wt == WIRE_SFIXED64 {
                (bits as i64).to_string()
            } else {
                bits.to_string()
            };
            Ok((s, p + 8))
        }
        WIRE_BOOL_FALSE => {
            let b = *body
                .get(p)
                .ok_or_else(|| Error::parse(format!("truncated WireMap bool key at {p}")))?;
            match b {
                0 => Ok(("false".to_owned(), p + 1)),
                1 => Ok(("true".to_owned(), p + 1)),
                _ => Err(Error::parse(format!("invalid WireMap bool key {b} at {p}"))),
            }
        }
        _ => Err(Error::parse(format!(
            "invalid WireMap key wire type {key_wt}"
        ))),
    }
}

fn decode_map_val_blind(
    body: &[u8],
    p: usize,
    val_wt: u8,
    child_layers: &[&SchemaMeta],
    depth: usize,
    budget: &mut BlindBudget,
) -> Result<(BlindValue, usize)> {
    match val_wt {
        WIRE_UINT => {
            let (v, vn) = decode_varint(&body[p..])
                .ok_or_else(|| Error::parse(format!("truncated WireMap uint val at {p}")))?;
            Ok((BlindValue::Uint(v), p + vn))
        }
        WIRE_SINT => {
            let (v, vn) = decode_varint(&body[p..])
                .ok_or_else(|| Error::parse(format!("truncated WireMap sint val at {p}")))?;
            Ok((BlindValue::Int(decode_zigzag(v)), p + vn))
        }
        WIRE_STRING => {
            let (s, next_p) = read_str_slice(body, p)?;
            budget.add_alloc(s.len())?;
            Ok((BlindValue::String(s.to_owned()), next_p))
        }
        WIRE_BYTES => {
            let (b, next_p) = read_len_slice(body, p, 0)?;
            budget.add_alloc(b.len())?;
            Ok((BlindValue::Bytes(b.to_vec()), next_p))
        }
        WIRE_SUB_MSG => {
            let (sub, next_p) = read_len_slice(body, p, 0)?;
            let map = decode_with_layers(sub, child_layers, depth + 1, budget)?;
            Ok((BlindValue::Object(map), next_p))
        }
        WIRE_ARRAY => {
            let (nested, next_p) = read_len_slice(body, p, 2)?;
            let mut arr = Vec::new();
            decode_array_blind(&mut arr, nested, child_layers, depth + 1, budget)?;
            Ok((BlindValue::Array(arr), next_p))
        }
        WIRE_MAP => {
            let (nested, next_p) = read_len_slice(body, p, 3)?;
            let mut map = BTreeMap::new();
            decode_map_body_blind(&mut map, nested, child_layers, depth + 1, budget)?;
            Ok((BlindValue::Object(map), next_p))
        }
        WIRE_FIXED32 | WIRE_FLOAT32 | WIRE_SFIXED32 => {
            let raw: [u8; 4] = body
                .get(p..p + 4)
                .ok_or_else(|| Error::parse(format!("truncated 32-bit value at {p}")))?
                .try_into()
                .unwrap();
            let bits = u32::from_le_bytes(raw);
            let v = match val_wt {
                WIRE_FLOAT32 => BlindValue::Float32(f32::from_bits(bits)),
                WIRE_SFIXED32 => BlindValue::Int(i64::from(bits as i32)),
                _ => BlindValue::Uint(u64::from(bits)),
            };
            Ok((v, p + 4))
        }
        WIRE_FIXED64 | WIRE_FLOAT64 | WIRE_SFIXED64 => {
            let raw: [u8; 8] = body
                .get(p..p + 8)
                .ok_or_else(|| Error::parse(format!("truncated 64-bit value at {p}")))?
                .try_into()
                .unwrap();
            let bits = u64::from_le_bytes(raw);
            let v = match val_wt {
                WIRE_FLOAT64 => BlindValue::Float64(f64::from_bits(bits)),
                WIRE_SFIXED64 => BlindValue::Int(bits as i64),
                _ => BlindValue::Uint(bits),
            };
            Ok((v, p + 8))
        }
        WIRE_BOOL_FALSE => {
            let b = *body
                .get(p)
                .ok_or_else(|| Error::parse(format!("truncated bool value at {p}")))?;
            match b {
                0 => Ok((BlindValue::Bool(false), p + 1)),
                1 => Ok((BlindValue::Bool(true), p + 1)),
                _ => Err(Error::parse(format!("invalid bool byte {b} at {p}"))),
            }
        }
        WIRE_EXTENDED => {
            let _ = read_len_slice(body, p, 1)?;
            Err(Error::parse("unknown extension"))
        }
        _ => Err(Error::parse(format!(
            "invalid WireMap value wire type {val_wt}"
        ))),
    }
}

// ============================================================================
// Canonical Blind JSON Serialization (64-bit Exact Ints + 32-bit Ryu Floats)
// ============================================================================

fn write_escaped_json_str(dst: &mut String, s: &str) {
    dst.push('"');
    for ch in s.chars() {
        match ch {
            '"' => dst.push_str("\\\""),
            '\\' => dst.push_str("\\\\"),
            '\x08' => dst.push_str("\\b"),
            '\x0c' => dst.push_str("\\f"),
            '\n' => dst.push_str("\\n"),
            '\r' => dst.push_str("\\r"),
            '\t' => dst.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                dst.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => dst.push(c),
        }
    }
    dst.push('"');
}

fn write_ryu_trimmed(dst: &mut String, formatted: &str) {
    if formatted != "-0.0"
        && let Some(stripped) = formatted.strip_suffix(".0")
    {
        dst.push_str(stripped);
    } else {
        dst.push_str(formatted);
    }
}

fn serialize_blind_value(
    dst: &mut String,
    val: &BlindValue,
    step: &str,
    cur_indent: &str,
    has_non_finite: &mut bool,
) {
    match val {
        BlindValue::Bool(b) => dst.push_str(if *b { "true" } else { "false" }),
        BlindValue::Uint(u) => {
            let mut buf = itoa::Buffer::new();
            dst.push_str(buf.format(*u));
        }
        BlindValue::Int(i) => {
            let mut buf = itoa::Buffer::new();
            dst.push_str(buf.format(*i));
        }
        BlindValue::Float32(f) => {
            if !f.is_finite() {
                *has_non_finite = true;
                dst.push_str("null");
            } else {
                let mut buf = ryu::Buffer::new();
                write_ryu_trimmed(dst, buf.format_finite(*f));
            }
        }
        BlindValue::Float64(f) => {
            if !f.is_finite() {
                *has_non_finite = true;
                dst.push_str("null");
            } else {
                let mut buf = ryu::Buffer::new();
                write_ryu_trimmed(dst, buf.format_finite(*f));
            }
        }
        BlindValue::String(s) => write_escaped_json_str(dst, s),
        BlindValue::Bytes(b) => {
            let b64 = encode_base64(b);
            write_escaped_json_str(dst, &b64);
        }
        BlindValue::Array(items) => {
            if items.is_empty() {
                dst.push_str("[]");
                return;
            }
            if step.is_empty() {
                dst.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        dst.push(',');
                    }
                    serialize_blind_value(dst, item, step, "", has_non_finite);
                }
                dst.push(']');
            } else {
                let next_indent = format!("{cur_indent}{step}");
                dst.push_str("[\n");
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        dst.push_str(",\n");
                    }
                    dst.push_str(&next_indent);
                    serialize_blind_value(dst, item, step, &next_indent, has_non_finite);
                }
                dst.push('\n');
                dst.push_str(cur_indent);
                dst.push(']');
            }
        }
        BlindValue::Object(map) => {
            serialize_blind_object(dst, map, step, cur_indent, has_non_finite);
        }
    }
}

fn serialize_blind_object(
    dst: &mut String,
    map: &BTreeMap<String, BlindValue>,
    step: &str,
    cur_indent: &str,
    has_non_finite: &mut bool,
) {
    if map.is_empty() {
        dst.push_str("{}");
        return;
    }
    if step.is_empty() {
        dst.push('{');
        for (i, (k, v)) in map.iter().enumerate() {
            if i > 0 {
                dst.push(',');
            }
            write_escaped_json_str(dst, k);
            dst.push(':');
            serialize_blind_value(dst, v, step, "", has_non_finite);
        }
        dst.push('}');
    } else {
        let next_indent = format!("{cur_indent}{step}");
        dst.push_str("{\n");
        for (i, (k, v)) in map.iter().enumerate() {
            if i > 0 {
                dst.push_str(",\n");
            }
            dst.push_str(&next_indent);
            write_escaped_json_str(dst, k);
            dst.push_str(": ");
            serialize_blind_value(dst, v, step, &next_indent, has_non_finite);
        }
        dst.push('\n');
        dst.push_str(cur_indent);
        dst.push('}');
    }
}

/// Formats a blind-decoded `BTreeMap<String, BlindValue>` as canonical JSON.
///
/// Emits exact 64-bit integers (`u64`/`i64`), shortest 32-bit `ryu` floats for `WireFloat32`,
/// and standard Base64 strings for `WireBytes`. When `fallback_on_non_finite` is `true`,
/// packets containing `NaN` or `Infinity` return `"{}"`.
pub fn stringify_blind_json(
    map: &BTreeMap<String, BlindValue>,
    indent: Option<usize>,
    fallback_on_non_finite: bool,
) -> String {
    let step = match indent {
        Some(n) if n > 0 => " ".repeat(n.min(10)),
        _ => String::new(),
    };
    let mut dst = String::with_capacity(map.len() * 24 + 2);
    let mut has_non_finite = false;
    serialize_blind_object(&mut dst, map, &step, "", &mut has_non_finite);
    if has_non_finite && fallback_on_non_finite {
        return "{}".to_owned();
    }
    dst
}

/// Decodes `packet` without a schema and serializes the result to canonical JSON.
///
/// Returns [`Error::Serialize`] if `packet` contains `NaN` or `Infinity`, which have no
/// standard JSON number representation.
pub fn decode_blind_json(packet: &[u8]) -> Result<String> {
    let map = decode_blind(packet)?;
    let mut dst = String::with_capacity(map.len() * 24 + 2);
    let mut has_non_finite = false;
    serialize_blind_object(&mut dst, &map, "", "", &mut has_non_finite);
    if has_non_finite {
        return Err(Error::serialize(
            "non-finite floating-point value cannot be represented in JSON",
        ));
    }
    Ok(dst)
}
