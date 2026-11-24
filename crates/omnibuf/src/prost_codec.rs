use std::collections::HashSet;

use prost::bytes::Bytes;
use prost_reflect::{
    DynamicMessage, FieldDescriptor, Kind, MapKey, MessageDescriptor, ReflectMessage, Value,
};

use crate::error::{Error, Result};
use crate::field0::{SchemaMeta, merge_schema_meta, validate_field0};
use crate::message::{
    AllocBudgetGuard, DecodeOptions, EncodeOptions, charge_typed_alloc,
    enforce_decode_options_with_schema_alloc,
};
use crate::wire::{
    MAX_FIELD_NUMBER, MAX_NESTING_DEPTH, WIRE_ARRAY, WIRE_BOOL_FALSE, WIRE_BOOL_TRUE, WIRE_BYTES,
    WIRE_FIXED32, WIRE_FIXED64, WIRE_FLOAT32, WIRE_FLOAT64, WIRE_MAP, WIRE_SFIXED32, WIRE_SFIXED64,
    WIRE_SINT, WIRE_STRING, WIRE_SUB_MSG, WIRE_UINT, append_tag, append_varint,
    backpatch_container_len, decode_varint, decode_zigzag, encode_zigzag, parse_array_header,
    parse_map_header, read_len_slice, read_str_slice, validate_value,
};

/// Builds an OmniBuf [`SchemaMeta`] from a Protobuf [`MessageDescriptor`], bounding cycles and depth.
pub fn schema_meta_from_descriptor(desc: &MessageDescriptor) -> SchemaMeta {
    let mut active = HashSet::new();
    build_descriptor_schema_meta(desc, 1, &mut active)
        .0
        .unwrap_or_default()
}

fn build_descriptor_schema_meta(
    desc: &MessageDescriptor,
    depth: usize,
    active: &mut HashSet<String>,
) -> (Option<SchemaMeta>, bool) {
    if depth >= MAX_NESTING_DEPTH {
        return (None, false);
    }
    let full_name = desc.full_name();
    let mut meta = SchemaMeta {
        type_name: desc.name().to_owned(),
        ..SchemaMeta::default()
    };

    for fd in desc.fields() {
        meta.fields.insert(fd.number(), fd.name().to_owned());
    }

    if active.contains(full_name) {
        return (Some(meta), true);
    }
    active.insert(full_name.to_owned());
    let mut cyclic = false;

    for fd in desc.fields() {
        if fd.is_group() {
            continue;
        }
        let fnum = fd.number();
        let child_desc = if fd.is_map() {
            if let Kind::Message(entry_desc) = fd.kind() {
                let val_fd = entry_desc.map_entry_value_field();
                if let Kind::Message(val_msg) = val_fd.kind() {
                    Some(val_msg)
                } else {
                    None
                }
            } else {
                None
            }
        } else if let Kind::Message(sub_desc) = fd.kind() {
            Some(sub_desc)
        } else {
            None
        };

        if let Some(sub_desc) = child_desc {
            let (child_opt, child_cyclic) =
                build_descriptor_schema_meta(&sub_desc, depth + 2, active);
            if child_cyclic {
                cyclic = true;
            }
            if let Some(child_meta) = child_opt {
                meta.children.insert(fnum, child_meta);
            }
        }
    }

    active.remove(full_name);
    (Some(meta), cyclic)
}

fn build_dynamic_value_schema_meta(msg: &DynamicMessage, depth: usize) -> Option<SchemaMeta> {
    if depth >= MAX_NESTING_DEPTH {
        return None;
    }
    let desc = msg.descriptor();
    let mut meta = SchemaMeta {
        type_name: desc.name().to_owned(),
        ..SchemaMeta::default()
    };

    for fd in desc.fields() {
        meta.fields.insert(fd.number(), fd.name().to_owned());
    }

    if depth + 2 >= MAX_NESTING_DEPTH {
        return Some(meta);
    }

    for fd in desc.fields() {
        if fd.is_group() || !msg.has_field(&fd) {
            continue;
        }
        let fnum = fd.number();
        let val = msg.get_field(&fd);
        let mut child: Option<SchemaMeta> = None;

        if fd.is_map() {
            if let Kind::Message(entry_desc) = fd.kind()
                && matches!(entry_desc.map_entry_value_field().kind(), Kind::Message(_))
                && let Value::Map(ref map) = *val
            {
                for v in map.values() {
                    if let Value::Message(sub) = v
                        && let Some(cm) = build_dynamic_value_schema_meta(sub, depth + 2)
                    {
                        child = Some(merge_schema_meta(child, cm));
                    }
                }
            }
        } else if fd.is_list() {
            if matches!(fd.kind(), Kind::Message(_))
                && let Value::List(ref list) = *val
            {
                for item in list {
                    if let Value::Message(sub) = item
                        && let Some(cm) = build_dynamic_value_schema_meta(sub, depth + 2)
                    {
                        child = Some(merge_schema_meta(child, cm));
                    }
                }
            }
        } else if matches!(fd.kind(), Kind::Message(_))
            && let Value::Message(ref sub) = *val
        {
            child = build_dynamic_value_schema_meta(sub, depth + 2);
        }

        if let Some(c) = child {
            meta.children.insert(fnum, c);
        }
    }

    Some(meta)
}

/// Encodes a [`DynamicMessage`] directly into OmniBuf wire bytes.
pub fn encode_dynamic(msg: &DynamicMessage, opts: EncodeOptions) -> Result<Vec<u8>> {
    let mut dst = Vec::with_capacity(128);
    encode_dynamic_append(&mut dst, msg, opts)?;
    Ok(dst)
}

/// Appends the OmniBuf encoding of a [`DynamicMessage`] to `dst`.
pub fn encode_dynamic_append(
    dst: &mut Vec<u8>,
    msg: &DynamicMessage,
    opts: EncodeOptions,
) -> Result<()> {
    if opts.self_describing {
        let mut active = HashSet::new();
        let (static_meta, cyclic) = build_descriptor_schema_meta(&msg.descriptor(), 1, &mut active);
        let meta = if cyclic {
            build_dynamic_value_schema_meta(msg, 1).unwrap_or_default()
        } else {
            static_meta.unwrap_or_default()
        };
        meta.append_field0(dst)?;
    }
    encode_dynamic_body(dst, msg, opts.deterministic)
}

/// Decodes OmniBuf wire bytes into a [`DynamicMessage`], clearing fields absent from `data`.
pub fn decode_dynamic(data: &[u8], msg: &mut DynamicMessage) -> Result<()> {
    decode_dynamic_at_depth(data, msg, 0, false)
}

/// Decodes OmniBuf wire bytes into a [`DynamicMessage`] while enforcing [`DecodeOptions`].
pub fn decode_dynamic_with_options(
    data: &[u8],
    msg: &mut DynamicMessage,
    opts: DecodeOptions,
) -> Result<()> {
    let schema_alloc = enforce_decode_options_with_schema_alloc(data, &opts)?;
    let _guard = AllocBudgetGuard::new(opts.max_alloc_bytes.saturating_sub(schema_alloc));
    decode_dynamic_at_depth(data, msg, 0, false)
}

/// Encodes any [`ReflectMessage`] into OmniBuf wire bytes.
pub fn encode_prost<M: ReflectMessage>(msg: &M, opts: EncodeOptions) -> Result<Vec<u8>> {
    let dyn_msg = msg.transcode_to_dynamic();
    encode_dynamic(&dyn_msg, opts)
}

/// Decodes OmniBuf wire bytes into any [`ReflectMessage`], resetting absent fields on `msg`.
pub fn decode_prost<M: ReflectMessage + Default>(data: &[u8], msg: &mut M) -> Result<()> {
    let mut dyn_msg = DynamicMessage::new(msg.descriptor());
    decode_dynamic_at_depth(data, &mut dyn_msg, 0, false)?;
    msg.clear();
    let mut proto_buf = Vec::with_capacity(data.len() + 32);
    encode_dynamic_to_proto_bytes(&dyn_msg, &mut proto_buf)?;
    msg.merge(proto_buf.as_slice())
        .map_err(|e| Error::parse(format!("prost transcode merge failed: {e}")))
}

/// Decodes OmniBuf wire bytes into any [`ReflectMessage`] while enforcing [`DecodeOptions`].
pub fn decode_prost_with_options<M: ReflectMessage + Default>(
    data: &[u8],
    msg: &mut M,
    opts: DecodeOptions,
) -> Result<()> {
    let schema_alloc = enforce_decode_options_with_schema_alloc(data, &opts)?;
    let _guard = AllocBudgetGuard::new(opts.max_alloc_bytes.saturating_sub(schema_alloc));
    decode_prost(data, msg)
}

fn proto_kind_wire_type(kind: &Kind) -> Result<u8> {
    match kind {
        Kind::Uint32 | Kind::Uint64 => Ok(WIRE_UINT),
        Kind::Enum(_) | Kind::Int32 | Kind::Sint32 | Kind::Int64 | Kind::Sint64 => Ok(WIRE_SINT),
        Kind::Bool => Ok(WIRE_BOOL_FALSE),
        Kind::Fixed32 => Ok(WIRE_FIXED32),
        Kind::Fixed64 => Ok(WIRE_FIXED64),
        Kind::Sfixed32 => Ok(WIRE_SFIXED32),
        Kind::Sfixed64 => Ok(WIRE_SFIXED64),
        Kind::Float => Ok(WIRE_FLOAT32),
        Kind::Double => Ok(WIRE_FLOAT64),
        Kind::String => Ok(WIRE_STRING),
        Kind::Bytes => Ok(WIRE_BYTES),
        Kind::Message(_) => Ok(WIRE_SUB_MSG),
    }
}

fn append_proto_scalar_payload(dst: &mut Vec<u8>, kind: &Kind, val: &Value) -> Result<()> {
    match (kind, val) {
        (Kind::Bool, Value::Bool(b)) => {
            dst.push(u8::from(*b));
            Ok(())
        }
        (Kind::Uint32, Value::U32(v)) => {
            append_varint(dst, u64::from(*v));
            Ok(())
        }
        (Kind::Uint64, Value::U64(v)) => {
            append_varint(dst, *v);
            Ok(())
        }
        (Kind::Enum(_), Value::EnumNumber(n)) => {
            append_varint(dst, encode_zigzag(i64::from(*n)));
            Ok(())
        }
        (Kind::Int32 | Kind::Sint32, Value::I32(v)) => {
            append_varint(dst, encode_zigzag(i64::from(*v)));
            Ok(())
        }
        (Kind::Int64 | Kind::Sint64, Value::I64(v)) => {
            append_varint(dst, encode_zigzag(*v));
            Ok(())
        }
        (Kind::String, Value::String(s)) => {
            append_varint(dst, s.len() as u64);
            dst.extend_from_slice(s.as_bytes());
            Ok(())
        }
        (Kind::Bytes, Value::Bytes(b)) => {
            append_varint(dst, b.len() as u64);
            dst.extend_from_slice(b);
            Ok(())
        }
        (Kind::Float, Value::F32(f)) => {
            dst.extend_from_slice(&f.to_bits().to_le_bytes());
            Ok(())
        }
        (Kind::Fixed32, Value::U32(v)) => {
            dst.extend_from_slice(&v.to_le_bytes());
            Ok(())
        }
        (Kind::Sfixed32, Value::I32(v)) => {
            dst.extend_from_slice(&v.to_le_bytes());
            Ok(())
        }
        (Kind::Double, Value::F64(f)) => {
            dst.extend_from_slice(&f.to_bits().to_le_bytes());
            Ok(())
        }
        (Kind::Fixed64, Value::U64(v)) => {
            dst.extend_from_slice(&v.to_le_bytes());
            Ok(())
        }
        (Kind::Sfixed64, Value::I64(v)) => {
            dst.extend_from_slice(&v.to_le_bytes());
            Ok(())
        }
        _ => Err(Error::serialize(format!(
            "mismatched prost Value {val:?} for Kind {kind:?}"
        ))),
    }
}

fn append_map_key_payload(dst: &mut Vec<u8>, kind: &Kind, key: &MapKey) -> Result<()> {
    match (kind, key) {
        (Kind::Bool, MapKey::Bool(b)) => {
            dst.push(u8::from(*b));
            Ok(())
        }
        (Kind::Uint32, MapKey::U32(v)) => {
            append_varint(dst, u64::from(*v));
            Ok(())
        }
        (Kind::Uint64, MapKey::U64(v)) => {
            append_varint(dst, *v);
            Ok(())
        }
        (Kind::Int32 | Kind::Sint32, MapKey::I32(v)) => {
            append_varint(dst, encode_zigzag(i64::from(*v)));
            Ok(())
        }
        (Kind::Int64 | Kind::Sint64, MapKey::I64(v)) => {
            append_varint(dst, encode_zigzag(*v));
            Ok(())
        }
        (Kind::Fixed32, MapKey::U32(v)) => {
            dst.extend_from_slice(&v.to_le_bytes());
            Ok(())
        }
        (Kind::Fixed64, MapKey::U64(v)) => {
            dst.extend_from_slice(&v.to_le_bytes());
            Ok(())
        }
        (Kind::Sfixed32, MapKey::I32(v)) => {
            dst.extend_from_slice(&v.to_le_bytes());
            Ok(())
        }
        (Kind::Sfixed64, MapKey::I64(v)) => {
            dst.extend_from_slice(&v.to_le_bytes());
            Ok(())
        }
        (Kind::String, MapKey::String(s)) => {
            append_varint(dst, s.len() as u64);
            dst.extend_from_slice(s.as_bytes());
            Ok(())
        }
        _ => Err(Error::serialize(format!(
            "unsupported map key {key:?} for Kind {kind:?}"
        ))),
    }
}

fn append_map_val_payload(
    dst: &mut Vec<u8>,
    val_fd: &FieldDescriptor,
    val: &Value,
    deterministic: bool,
) -> Result<()> {
    if val_fd.is_group() {
        return Err(Error::serialize(
            "proto2 groups are not supported by OmniBuf",
        ));
    }
    if let (Kind::Message(_), Value::Message(sub_msg)) = (val_fd.kind(), val) {
        let len_pos = dst.len();
        dst.extend_from_slice(&[0, 0]);
        encode_dynamic_body(dst, sub_msg, deterministic)?;
        backpatch_container_len(dst, len_pos);
        Ok(())
    } else {
        append_proto_scalar_payload(dst, &val_fd.kind(), val)
    }
}

fn encode_dynamic_body(dst: &mut Vec<u8>, msg: &DynamicMessage, deterministic: bool) -> Result<()> {
    let desc = msg.descriptor();
    for ext in desc.extensions() {
        if msg.has_extension(&ext) {
            return Err(Error::serialize(format!(
                "proto2 extensions are not supported by OmniBuf: {}",
                ext.full_name()
            )));
        }
    }
    let mut ordered_fields: Vec<_> = desc.fields().collect();
    ordered_fields.sort_by_key(|f| f.number());
    for fd in ordered_fields {
        if fd.is_group() {
            return Err(Error::serialize(format!(
                "proto2 groups are not supported by OmniBuf: {}",
                fd.full_name()
            )));
        }
        let fnum = fd.number();
        if fd.supports_presence() && !msg.has_field(&fd) {
            continue;
        }
        let val = msg.get_field(&fd);

        if fd.is_map() {
            let Kind::Message(entry_desc) = fd.kind() else {
                return Err(Error::serialize("invalid map entry descriptor"));
            };
            let key_fd = entry_desc.map_entry_key_field();
            let val_fd = entry_desc.map_entry_value_field();
            if val_fd.is_group() {
                return Err(Error::serialize(
                    "proto2 groups are not supported by OmniBuf",
                ));
            }
            let key_wt = proto_kind_wire_type(&key_fd.kind())?;
            let val_wt = proto_kind_wire_type(&val_fd.kind())?;
            let Value::Map(ref map) = *val else {
                return Err(Error::serialize("expected Value::Map for map field"));
            };

            append_tag(dst, fnum, WIRE_MAP);
            let len_pos = dst.len();
            dst.extend_from_slice(&[0, 0, key_wt, val_wt]);
            append_varint(dst, map.len() as u64);
            if deterministic && map.len() > 1 {
                let mut keys: Vec<&MapKey> = map.keys().collect();
                keys.sort();
                for k in keys {
                    append_map_key_payload(dst, &key_fd.kind(), k)?;
                    append_map_val_payload(dst, &val_fd, &map[k], deterministic)?;
                }
            } else {
                for (k, v) in map {
                    append_map_key_payload(dst, &key_fd.kind(), k)?;
                    append_map_val_payload(dst, &val_fd, v, deterministic)?;
                }
            }
            backpatch_container_len(dst, len_pos);
            continue;
        }

        if fd.is_list() {
            let elem_wt = proto_kind_wire_type(&fd.kind())?;
            let Value::List(ref list) = *val else {
                return Err(Error::serialize("expected Value::List for repeated field"));
            };
            append_tag(dst, fnum, WIRE_ARRAY);
            let len_pos = dst.len();
            dst.extend_from_slice(&[0, 0, elem_wt]);
            append_varint(dst, list.len() as u64);
            for item in list {
                if let Value::Message(sub_msg) = item {
                    let elem_pos = dst.len();
                    dst.extend_from_slice(&[0, 0]);
                    encode_dynamic_body(dst, sub_msg, deterministic)?;
                    backpatch_container_len(dst, elem_pos);
                } else {
                    append_proto_scalar_payload(dst, &fd.kind(), item)?;
                }
            }
            backpatch_container_len(dst, len_pos);
            continue;
        }

        match (&fd.kind(), &*val) {
            (Kind::Message(_), Value::Message(sub_msg)) => {
                if !msg.has_field(&fd) {
                    continue;
                }
                append_tag(dst, fnum, WIRE_SUB_MSG);
                let len_pos = dst.len();
                dst.extend_from_slice(&[0, 0]);
                encode_dynamic_body(dst, sub_msg, deterministic)?;
                backpatch_container_len(dst, len_pos);
            }
            (Kind::Bool, Value::Bool(b)) => {
                append_tag(dst, fnum, if *b { WIRE_BOOL_TRUE } else { WIRE_BOOL_FALSE });
            }
            (kind, v) => {
                let wt = proto_kind_wire_type(kind)?;
                append_tag(dst, fnum, wt);
                append_proto_scalar_payload(dst, kind, v)?;
            }
        }
    }
    Ok(())
}

fn decode_proto_scalar_payload(data: &[u8], pos: usize, kind: &Kind) -> Result<(Value, usize)> {
    match kind {
        Kind::Bool => {
            let b = *data
                .get(pos)
                .ok_or_else(|| Error::parse(format!("truncated bool at {pos}")))?;
            if b > 1 {
                return Err(Error::parse(format!("invalid bool byte {b} at {pos}")));
            }
            Ok((Value::Bool(b == 1), pos + 1))
        }
        Kind::Uint32 => {
            let (v, vn) = decode_varint(
                data.get(pos..)
                    .ok_or_else(|| Error::parse("uint32 out of bounds"))?,
            )
            .ok_or_else(|| Error::parse(format!("truncated uint32 at {pos}")))?;
            Ok((Value::U32(v as u32), pos + vn))
        }
        Kind::Uint64 => {
            let (v, vn) = decode_varint(
                data.get(pos..)
                    .ok_or_else(|| Error::parse("uint64 out of bounds"))?,
            )
            .ok_or_else(|| Error::parse(format!("truncated uint64 at {pos}")))?;
            Ok((Value::U64(v), pos + vn))
        }
        Kind::Enum(_) => {
            let (v, vn) = decode_varint(
                data.get(pos..)
                    .ok_or_else(|| Error::parse("enum out of bounds"))?,
            )
            .ok_or_else(|| Error::parse(format!("truncated enum at {pos}")))?;
            Ok((Value::EnumNumber(decode_zigzag(v) as i32), pos + vn))
        }
        Kind::Int32 | Kind::Sint32 => {
            let (v, vn) = decode_varint(
                data.get(pos..)
                    .ok_or_else(|| Error::parse("int32 out of bounds"))?,
            )
            .ok_or_else(|| Error::parse(format!("truncated int32 at {pos}")))?;
            Ok((Value::I32(decode_zigzag(v) as i32), pos + vn))
        }
        Kind::Int64 | Kind::Sint64 => {
            let (v, vn) = decode_varint(
                data.get(pos..)
                    .ok_or_else(|| Error::parse("int64 out of bounds"))?,
            )
            .ok_or_else(|| Error::parse(format!("truncated int64 at {pos}")))?;
            Ok((Value::I64(decode_zigzag(v)), pos + vn))
        }
        Kind::String => {
            let (s, next_pos) = read_str_slice(data, pos)?;
            Ok((Value::String(s.to_owned()), next_pos))
        }
        Kind::Bytes => {
            let (b, next_pos) = read_len_slice(data, pos, 0)?;
            Ok((Value::Bytes(Bytes::copy_from_slice(b)), next_pos))
        }
        Kind::Float | Kind::Fixed32 | Kind::Sfixed32 => {
            let raw: [u8; 4] = data
                .get(pos..pos + 4)
                .ok_or_else(|| Error::parse(format!("truncated 32-bit scalar at {pos}")))?
                .try_into()
                .unwrap();
            let bits = u32::from_le_bytes(raw);
            let val = match kind {
                Kind::Float => Value::F32(f32::from_bits(bits)),
                Kind::Fixed32 => Value::U32(bits),
                _ => Value::I32(bits as i32),
            };
            Ok((val, pos + 4))
        }
        Kind::Double | Kind::Fixed64 | Kind::Sfixed64 => {
            let raw: [u8; 8] = data
                .get(pos..pos + 8)
                .ok_or_else(|| Error::parse(format!("truncated 64-bit scalar at {pos}")))?
                .try_into()
                .unwrap();
            let bits = u64::from_le_bytes(raw);
            let val = match kind {
                Kind::Double => Value::F64(f64::from_bits(bits)),
                Kind::Fixed64 => Value::U64(bits),
                _ => Value::I64(bits as i64),
            };
            Ok((val, pos + 8))
        }
        Kind::Message(_) => Err(Error::parse("unexpected Kind::Message in scalar decoder")),
    }
}

fn value_to_map_key(val: Value) -> Result<MapKey> {
    match val {
        Value::Bool(b) => Ok(MapKey::Bool(b)),
        Value::I32(v) => Ok(MapKey::I32(v)),
        Value::I64(v) => Ok(MapKey::I64(v)),
        Value::U32(v) => Ok(MapKey::U32(v)),
        Value::U64(v) => Ok(MapKey::U64(v)),
        Value::String(s) => Ok(MapKey::String(s)),
        other => Err(Error::parse(format!("invalid map key value {other:?}"))),
    }
}

fn decode_dynamic_at_depth(
    data: &[u8],
    msg: &mut DynamicMessage,
    depth: usize,
    merge: bool,
) -> Result<()> {
    if depth > MAX_NESTING_DEPTH {
        return Err(Error::DepthLimitExceeded(depth));
    }
    let desc = msg.descriptor();
    for fd in desc.fields() {
        if fd.is_group() {
            return Err(Error::parse(format!(
                "proto2 groups are not supported by OmniBuf: {}",
                fd.full_name()
            )));
        }
    }

    if !merge {
        *msg = DynamicMessage::new(desc.clone());
    }

    let n = data.len();
    let mut pos = 0usize;

    while pos < n {
        let (tag, tn) = decode_varint(&data[pos..])
            .ok_or_else(|| Error::parse(format!("truncated or invalid tag at {pos}")))?;
        if (tag >> 4) > MAX_FIELD_NUMBER {
            return Err(Error::parse("field number exceeds maximum 29-bit limit"));
        }
        pos += tn;
        let fnum = (tag >> 4) as u32;
        let wt = (tag & 0x0F) as u8;

        if fnum == 0 {
            if wt != WIRE_SUB_MSG {
                return Err(Error::parse(format!("invalid Field #0 wire type {wt}")));
            }
            pos = validate_field0(data, pos, depth)?;
            continue;
        }

        if let Some(ext) = desc.get_extension(fnum) {
            return Err(Error::parse(format!(
                "proto2 extensions are not supported by OmniBuf: {}",
                ext.full_name()
            )));
        }

        let Some(fd) = desc.get_field(fnum) else {
            pos = validate_value(data, pos, wt, depth)?;
            continue;
        };

        if fd.is_map() {
            if wt != WIRE_MAP {
                pos = validate_value(data, pos, wt, depth)?;
                continue;
            }
            if depth + 1 > MAX_NESTING_DEPTH {
                return Err(Error::DepthLimitExceeded(depth + 1));
            }

            let Kind::Message(entry_desc) = fd.kind() else {
                return Err(Error::parse("invalid map descriptor"));
            };
            let key_fd = entry_desc.map_entry_key_field();
            let val_fd = entry_desc.map_entry_value_field();
            if val_fd.is_group() {
                return Err(Error::parse("proto2 groups are not supported by OmniBuf"));
            }
            let exp_key_wt = proto_kind_wire_type(&key_fd.kind())?;
            let exp_val_wt = proto_kind_wire_type(&val_fd.kind())?;

            let (body, next_pos) = read_len_slice(data, pos, 3)?;
            let (key_wt, val_wt, count, mut p) =
                parse_map_header(body).ok_or_else(|| Error::parse("invalid WireMap header"))?;
            if key_wt != exp_key_wt || val_wt != exp_val_wt {
                return Err(Error::parse("WireMap key/value wire type mismatch"));
            }
            charge_typed_alloc(count.saturating_mul(core::mem::size_of::<(MapKey, Value)>()))?;

            let Value::Map(map) = msg.get_field_mut(&fd) else {
                return Err(Error::parse("expected Value::Map"));
            };
            for _ in 0..count {
                let (kv, after_k) = decode_proto_scalar_payload(body, p, &key_fd.kind())?;
                let mk = value_to_map_key(kv)?;
                let (mv, after_v) = if let Kind::Message(sub_desc) = val_fd.kind() {
                    let (sub_bytes, next_p) = read_len_slice(body, after_k, 0)?;
                    let mut sub_msg = DynamicMessage::new(sub_desc);
                    decode_dynamic_at_depth(sub_bytes, &mut sub_msg, depth + 2, false)?;
                    (Value::Message(sub_msg), next_p)
                } else {
                    decode_proto_scalar_payload(body, after_k, &val_fd.kind())?
                };
                map.insert(mk, mv);
                p = after_v;
            }
            if p != body.len() {
                return Err(Error::parse("WireMap trailing bytes"));
            }
            pos = next_pos;
            continue;
        }

        if fd.is_list() {
            if wt != WIRE_ARRAY {
                pos = validate_value(data, pos, wt, depth)?;
                continue;
            }
            if depth + 1 > MAX_NESTING_DEPTH {
                return Err(Error::DepthLimitExceeded(depth + 1));
            }

            let exp_elem_wt = proto_kind_wire_type(&fd.kind())?;
            let (body, next_pos) = read_len_slice(data, pos, 2)?;
            let (elem_wt, count, mut p) =
                parse_array_header(body).ok_or_else(|| Error::parse("invalid WireArray header"))?;
            if elem_wt != exp_elem_wt {
                return Err(Error::parse("WireArray element wire type mismatch"));
            }
            charge_typed_alloc(count.saturating_mul(core::mem::size_of::<Value>()))?;

            let Value::List(list) = msg.get_field_mut(&fd) else {
                return Err(Error::parse("expected Value::List"));
            };
            list.reserve(count.min(4096));
            for _ in 0..count {
                if let Kind::Message(sub_desc) = fd.kind() {
                    let (sub_bytes, next_p) = read_len_slice(body, p, 0)?;
                    let mut sub_msg = DynamicMessage::new(sub_desc);
                    decode_dynamic_at_depth(sub_bytes, &mut sub_msg, depth + 2, false)?;
                    list.push(Value::Message(sub_msg));
                    p = next_p;
                } else {
                    let (v, next_p) = decode_proto_scalar_payload(body, p, &fd.kind())?;
                    list.push(v);
                    p = next_p;
                }
            }
            if p != body.len() {
                return Err(Error::parse("WireArray trailing bytes"));
            }
            pos = next_pos;
            continue;
        }

        if matches!(fd.kind(), Kind::Bool) {
            if wt != WIRE_BOOL_FALSE && wt != WIRE_BOOL_TRUE {
                pos = validate_value(data, pos, wt, depth)?;
                continue;
            }
            msg.set_field(&fd, Value::Bool(wt == WIRE_BOOL_TRUE));
            continue;
        }

        let exp_wt = proto_kind_wire_type(&fd.kind())?;
        if wt != exp_wt {
            pos = validate_value(data, pos, wt, depth)?;
            continue;
        }

        if let Kind::Message(sub_desc) = fd.kind() {
            let (sub_bytes, next_pos) = read_len_slice(data, pos, 0)?;
            if !msg.has_field(&fd) {
                charge_typed_alloc(core::mem::size_of::<DynamicMessage>())?;
                let mut sub_msg = DynamicMessage::new(sub_desc);
                decode_dynamic_at_depth(sub_bytes, &mut sub_msg, depth + 1, false)?;
                msg.set_field(&fd, Value::Message(sub_msg));
            } else if let Value::Message(sub_msg) = msg.get_field_mut(&fd) {
                decode_dynamic_at_depth(sub_bytes, sub_msg, depth + 1, true)?;
            }
            pos = next_pos;
            continue;
        }

        let (sv, next_pos) = decode_proto_scalar_payload(data, pos, &fd.kind())?;
        msg.set_field(&fd, sv);
        pos = next_pos;
    }

    Ok(())
}

fn write_proto_varint(dst: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        dst.push(((v as u8) & 0x7F) | 0x80);
        v >>= 7;
    }
    dst.push(v as u8);
}

fn write_proto_zigzag32(v: i32) -> u64 {
    (((v << 1) ^ (v >> 31)) as u32) as u64
}

fn write_proto_zigzag64(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

fn is_proto_default_scalar(kind: &Kind, val: &Value) -> bool {
    match (kind, val) {
        (Kind::Bool, Value::Bool(b)) => !*b,
        (Kind::Uint32 | Kind::Fixed32, Value::U32(v)) => *v == 0,
        (Kind::Uint64 | Kind::Fixed64, Value::U64(v)) => *v == 0,
        (Kind::Int32 | Kind::Sint32 | Kind::Sfixed32, Value::I32(v)) => *v == 0,
        (Kind::Int64 | Kind::Sint64 | Kind::Sfixed64, Value::I64(v)) => *v == 0,
        (Kind::Enum(_), Value::EnumNumber(n)) => *n == 0,
        (Kind::Float, Value::F32(f)) => f.to_bits() == 0,
        (Kind::Double, Value::F64(f)) => f.to_bits() == 0,
        (Kind::String, Value::String(s)) => s.is_empty(),
        (Kind::Bytes, Value::Bytes(b)) => b.is_empty(),
        _ => false,
    }
}

fn write_proto_tagged_scalar(dst: &mut Vec<u8>, fnum: u32, kind: &Kind, val: &Value) -> Result<()> {
    let f = u64::from(fnum);
    match (kind, val) {
        (Kind::Bool, Value::Bool(b)) => {
            write_proto_varint(dst, f << 3);
            dst.push(u8::from(*b));
        }
        (Kind::Uint32, Value::U32(v)) => {
            write_proto_varint(dst, f << 3);
            write_proto_varint(dst, u64::from(*v));
        }
        (Kind::Uint64, Value::U64(v)) => {
            write_proto_varint(dst, f << 3);
            write_proto_varint(dst, *v);
        }
        (Kind::Int32, Value::I32(v)) => {
            write_proto_varint(dst, f << 3);
            write_proto_varint(dst, i64::from(*v) as u64);
        }
        (Kind::Int64, Value::I64(v)) => {
            write_proto_varint(dst, f << 3);
            write_proto_varint(dst, *v as u64);
        }
        (Kind::Enum(_), Value::EnumNumber(n)) => {
            write_proto_varint(dst, f << 3);
            write_proto_varint(dst, i64::from(*n) as u64);
        }
        (Kind::Sint32, Value::I32(v)) => {
            write_proto_varint(dst, f << 3);
            write_proto_varint(dst, write_proto_zigzag32(*v));
        }
        (Kind::Sint64, Value::I64(v)) => {
            write_proto_varint(dst, f << 3);
            write_proto_varint(dst, write_proto_zigzag64(*v));
        }
        (Kind::Fixed32, Value::U32(v)) => {
            write_proto_varint(dst, (f << 3) | 5);
            dst.extend_from_slice(&v.to_le_bytes());
        }
        (Kind::Sfixed32, Value::I32(v)) => {
            write_proto_varint(dst, (f << 3) | 5);
            dst.extend_from_slice(&v.to_le_bytes());
        }
        (Kind::Float, Value::F32(v)) => {
            write_proto_varint(dst, (f << 3) | 5);
            dst.extend_from_slice(&v.to_bits().to_le_bytes());
        }
        (Kind::Fixed64, Value::U64(v)) => {
            write_proto_varint(dst, (f << 3) | 1);
            dst.extend_from_slice(&v.to_le_bytes());
        }
        (Kind::Sfixed64, Value::I64(v)) => {
            write_proto_varint(dst, (f << 3) | 1);
            dst.extend_from_slice(&v.to_le_bytes());
        }
        (Kind::Double, Value::F64(v)) => {
            write_proto_varint(dst, (f << 3) | 1);
            dst.extend_from_slice(&v.to_bits().to_le_bytes());
        }
        (Kind::String, Value::String(s)) => {
            write_proto_varint(dst, (f << 3) | 2);
            write_proto_varint(dst, s.len() as u64);
            dst.extend_from_slice(s.as_bytes());
        }
        (Kind::Bytes, Value::Bytes(b)) => {
            write_proto_varint(dst, (f << 3) | 2);
            write_proto_varint(dst, b.len() as u64);
            dst.extend_from_slice(b);
        }
        _ => {
            return Err(Error::parse(format!(
                "unexpected Value {val:?} for Kind {kind:?} during prost transcode"
            )));
        }
    }
    Ok(())
}

fn write_proto_map_key(dst: &mut Vec<u8>, kind: &Kind, key: &MapKey) -> Result<()> {
    match key {
        MapKey::Bool(b) => write_proto_tagged_scalar(dst, 1, kind, &Value::Bool(*b)),
        MapKey::I32(v) => write_proto_tagged_scalar(dst, 1, kind, &Value::I32(*v)),
        MapKey::I64(v) => write_proto_tagged_scalar(dst, 1, kind, &Value::I64(*v)),
        MapKey::U32(v) => write_proto_tagged_scalar(dst, 1, kind, &Value::U32(*v)),
        MapKey::U64(v) => write_proto_tagged_scalar(dst, 1, kind, &Value::U64(*v)),
        MapKey::String(s) => write_proto_tagged_scalar(dst, 1, kind, &Value::String(s.clone())),
    }
}

/// Encodes `dyn_msg` directly to Protobuf wire bytes while emitting `-0.0` float/double
/// sign bits explicitly across singular, repeated, map, and nested submessage fields.
fn encode_dynamic_to_proto_bytes(dyn_msg: &DynamicMessage, dst: &mut Vec<u8>) -> Result<()> {
    for fd in dyn_msg.descriptor().fields() {
        let fnum = fd.number();
        let kind = fd.kind();
        if fd.is_map() {
            let Kind::Message(entry_desc) = kind else {
                continue;
            };
            let key_kind = entry_desc.map_entry_key_field().kind();
            let val_kind = entry_desc.map_entry_value_field().kind();
            let val = dyn_msg.get_field(&fd);
            let Value::Map(ref map) = *val else {
                continue;
            };
            let mut entry_buf = Vec::new();
            for (k, v) in map {
                entry_buf.clear();
                write_proto_map_key(&mut entry_buf, &key_kind, k)?;
                if let Value::Message(sub_msg) = v {
                    let mut sub_buf = Vec::new();
                    encode_dynamic_to_proto_bytes(sub_msg, &mut sub_buf)?;
                    write_proto_varint(&mut entry_buf, (2 << 3) | 2);
                    write_proto_varint(&mut entry_buf, sub_buf.len() as u64);
                    entry_buf.extend_from_slice(&sub_buf);
                } else {
                    write_proto_tagged_scalar(&mut entry_buf, 2, &val_kind, v)?;
                }
                write_proto_varint(dst, (u64::from(fnum) << 3) | 2);
                write_proto_varint(dst, entry_buf.len() as u64);
                dst.extend_from_slice(&entry_buf);
            }
            continue;
        }

        if fd.is_list() {
            let val = dyn_msg.get_field(&fd);
            let Value::List(ref list) = *val else {
                continue;
            };
            let mut sub_buf = Vec::new();
            for item in list {
                if let Value::Message(sub_msg) = item {
                    sub_buf.clear();
                    encode_dynamic_to_proto_bytes(sub_msg, &mut sub_buf)?;
                    write_proto_varint(dst, (u64::from(fnum) << 3) | 2);
                    write_proto_varint(dst, sub_buf.len() as u64);
                    dst.extend_from_slice(&sub_buf);
                } else {
                    write_proto_tagged_scalar(dst, fnum, &kind, item)?;
                }
            }
            continue;
        }

        if fd.supports_presence() {
            if !dyn_msg.has_field(&fd) {
                continue;
            }
            let val = dyn_msg.get_field(&fd);
            if let Value::Message(ref sub_msg) = *val {
                let mut sub_buf = Vec::new();
                encode_dynamic_to_proto_bytes(sub_msg, &mut sub_buf)?;
                write_proto_varint(dst, (u64::from(fnum) << 3) | 2);
                write_proto_varint(dst, sub_buf.len() as u64);
                dst.extend_from_slice(&sub_buf);
            } else {
                write_proto_tagged_scalar(dst, fnum, &kind, &val)?;
            }
        } else {
            let val = dyn_msg.get_field(&fd);
            if !is_proto_default_scalar(&kind, &val) {
                write_proto_tagged_scalar(dst, fnum, &kind, &val)?;
            }
        }
    }
    Ok(())
}
