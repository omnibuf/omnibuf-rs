//! Bridge between OmniBuf wire packets and [`buffa`] / [`buffa_descriptor`] Protobuf messages.
//!
//! Enabled via `features = ["buffa"]` (active in default crate features). Two runtime paths
//! complement compile-time `#[derive(OmniBuf)]` co-derivation on `buffa-build` structs:
//!
//! 1. **In-place vtable reflection (`Reflectable` / `ReflectMessage`):** Setting
//!    `.generate_reflection(true)` (`ReflectMode::VTable`) in `buffa-build` lets
//!    [`encode_buffa_reflect`] walk `buffa` struct fields directly in memory with zero
//!    intermediate Protobuf serialization.
//! 2. **Descriptor-pool transcoding (`Message + MessageName`):** [`encode_buffa`] and
//!    [`decode_buffa`] transcode any `buffa` message against an `Arc<DescriptorPool>`,
//!    covering pre-compiled upstream crates where `generate_reflection` is off.
//!
//! Crates that control their own `build.rs` can attach `#[derive(::omnibuf::OmniBuf)]` via
//! `buffa_build::Config::message_attribute` and `oneof_attribute` for static monomorphized
//! codecs over `buffa::MessageField<T>`, `buffa::EnumValue<E>`, `Option<...>` oneofs, and
//! `/// Field N:` doc comments.
//!
//! # Examples
//!
//! Co-deriving `#[derive(OmniBuf)]` directly on `buffa`-style generated structs:
//!
//! ```rust
//! # #[cfg(feature = "derive")]
//! # {
//! use buffa::{EnumValue, Enumeration, MessageField};
//! use omnibuf::{Message, OmniBuf};
//!
//! #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
//! #[repr(i32)]
//! enum PeerRole {
//!     #[default]
//!     Unspecified = 0,
//!     Edge = 1,
//! }
//!
//! impl Enumeration for PeerRole {
//!     fn from_i32(v: i32) -> Option<Self> {
//!         match v {
//!             0 => Some(Self::Unspecified),
//!             1 => Some(Self::Edge),
//!             _ => None,
//!         }
//!     }
//!     fn to_i32(&self) -> i32 { *self as i32 }
//!     fn proto_name(&self) -> &'static str {
//!         match self {
//!             Self::Unspecified => "UNSPECIFIED",
//!             Self::Edge => "EDGE",
//!         }
//!     }
//! }
//!
//! #[derive(Debug, Default, OmniBuf)]
//! struct Endpoint {
//!     /// Field 1: `host`
//!     pub host: String,
//!     /// Field 2: `port`
//!     pub port: u32,
//!     pub __buffa_unknown_fields: buffa::UnknownFields,
//! }
//!
//! buffa::impl_default_instance!(Endpoint);
//!
//! #[derive(Debug, Default, OmniBuf)]
//! struct PeerLink {
//!     /// Field 1: `endpoint`
//!     pub endpoint: MessageField<Endpoint>,
//!     /// Field 2: `role`
//!     pub role: EnumValue<PeerRole>,
//!     pub __buffa_unknown_fields: buffa::UnknownFields,
//! }
//!
//! let link = PeerLink {
//!     endpoint: MessageField::some(Endpoint {
//!         host: "fra1-edge".into(),
//!         port: 179,
//!         ..Default::default()
//!     }),
//!     role: EnumValue::Known(PeerRole::Edge),
//!     ..Default::default()
//! };
//!
//! let wire = link.encode_omnibuf()?;
//! let decoded = PeerLink::from_omnibuf(&wire)?;
//! assert_eq!(decoded.endpoint.host, "fra1-edge");
//! assert_eq!(decoded.role, EnumValue::Known(PeerRole::Edge));
//! # }
//! # Ok::<(), omnibuf::Error>(())
//! ```
//!
//! Transcoding dynamically against a `buffa_descriptor::DescriptorPool`:
//!
//! ```rust
//! use std::sync::Arc;
//! use buffa_descriptor::generated::descriptor::{
//!     DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
//!     field_descriptor_proto::{Label, Type},
//! };
//! use buffa_descriptor::{
//!     DescriptorPool, DynamicMessage, ReflectMessage, ReflectMessageMut, Value, ValueRef,
//! };
//! use omnibuf::EncodeOptions;
//! use omnibuf::buffa_codec::{decode_buffa_dynamic, encode_buffa_dynamic};
//!
//! let fds = FileDescriptorSet {
//!     file: vec![FileDescriptorProto {
//!         name: Some("peer.proto".into()),
//!         package: Some("bench".into()),
//!         syntax: Some("proto3".into()),
//!         message_type: vec![DescriptorProto {
//!             name: Some("Peer".into()),
//!             field: vec![FieldDescriptorProto {
//!                 name: Some("router_id".into()),
//!                 number: Some(1),
//!                 label: Some(Label::LABEL_OPTIONAL),
//!                 r#type: Some(Type::TYPE_STRING),
//!                 ..Default::default()
//!             }],
//!             ..Default::default()
//!         }],
//!         ..Default::default()
//!     }],
//!     ..Default::default()
//! };
//!
//! let pool = Arc::new(DescriptorPool::new(fds).unwrap());
//! let idx = pool.message_index("bench.Peer").unwrap();
//! let fd = pool.message(idx).field_by_name("router_id").unwrap();
//!
//! let mut msg = DynamicMessage::new(Arc::clone(&pool), idx);
//! msg.set(fd, Value::String("edge-fra-01".into()));
//!
//! let wire = encode_buffa_dynamic(&msg, EncodeOptions::self_describing())?;
//! let mut out = DynamicMessage::new(Arc::clone(&pool), idx);
//! decode_buffa_dynamic(&wire, &mut out)?;
//! assert!(matches!(out.get(fd), ValueRef::String("edge-fra-01")));
//! # Ok::<(), omnibuf::Error>(())
//! ```

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use buffa::editions::FieldPresence;
use buffa::{Message as BuffaMessage, MessageName};
use buffa_descriptor::{
    DescriptorPool, DynamicMessage, FieldDescriptor, FieldKind, MapKey, MapKeyRef, MapValue,
    MessageDescriptor, MessageIndex, ReflectMessage, ReflectMessageMut, Reflectable, ScalarType,
    SingularKind, Value, ValueRef,
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

/// Builds an OmniBuf [`SchemaMeta`] from a `buffa` [`DescriptorPool`] and [`MessageIndex`].
pub fn schema_meta_from_buffa_descriptor(
    pool: &DescriptorPool,
    msg_idx: MessageIndex,
) -> SchemaMeta {
    let mut active = HashSet::new();
    build_buffa_schema_meta(pool, msg_idx, 1, &mut active)
        .0
        .unwrap_or_default()
}

/// Builds an OmniBuf [`SchemaMeta`] by looking up `full_name` in `pool`.
pub fn schema_meta_from_buffa_name(pool: &DescriptorPool, full_name: &str) -> Result<SchemaMeta> {
    let idx = pool.message_index(full_name).ok_or_else(|| {
        Error::serialize(format!("message {full_name:?} not found in buffa pool"))
    })?;
    Ok(schema_meta_from_buffa_descriptor(pool, idx))
}

fn short_message_name(md: &MessageDescriptor) -> &str {
    md.full_name()
        .rsplit('.')
        .next()
        .unwrap_or_else(|| md.full_name())
}

fn build_buffa_schema_meta(
    pool: &DescriptorPool,
    msg_idx: MessageIndex,
    depth: usize,
    active: &mut HashSet<MessageIndex>,
) -> (Option<SchemaMeta>, bool) {
    if depth >= MAX_NESTING_DEPTH {
        return (None, false);
    }
    let md = pool.message(msg_idx);
    let mut meta = SchemaMeta {
        type_name: short_message_name(md).to_owned(),
        ..SchemaMeta::default()
    };

    for fd in md.fields() {
        meta.fields.insert(fd.number(), fd.name().to_owned());
    }

    if active.contains(&msg_idx) {
        return (Some(meta), true);
    }
    active.insert(msg_idx);
    let mut cyclic = false;

    for fd in md.fields() {
        if fd.is_delimited() {
            continue;
        }
        let child_idx = match fd.kind() {
            FieldKind::Singular(SingularKind::Message(c))
            | FieldKind::List(SingularKind::Message(c))
            | FieldKind::Map {
                value: SingularKind::Message(c),
                ..
            } => Some(c),
            _ => None,
        };
        if let Some(cidx) = child_idx {
            let (child_opt, child_cyclic) = build_buffa_schema_meta(pool, cidx, depth + 2, active);
            if child_cyclic {
                cyclic = true;
            }
            if let Some(child_meta) = child_opt {
                meta.children.insert(fd.number(), child_meta);
            }
        }
    }

    active.remove(&msg_idx);
    (Some(meta), cyclic)
}

fn build_reflect_value_schema_meta(refl: &dyn ReflectMessage, depth: usize) -> Option<SchemaMeta> {
    if depth >= MAX_NESTING_DEPTH {
        return None;
    }
    let md = refl.message_descriptor();
    let mut meta = SchemaMeta {
        type_name: short_message_name(md).to_owned(),
        ..SchemaMeta::default()
    };

    for fd in md.fields() {
        meta.fields.insert(fd.number(), fd.name().to_owned());
    }

    if depth + 2 >= MAX_NESTING_DEPTH {
        return Some(meta);
    }

    for fd in md.fields() {
        if fd.is_delimited() || !refl.has(fd) {
            continue;
        }
        let fnum = fd.number();
        let mut child: Option<SchemaMeta> = None;

        match fd.kind() {
            FieldKind::Singular(SingularKind::Message(_)) => {
                if let ValueRef::Message(sub_cow) = refl.get(fd) {
                    child = build_reflect_value_schema_meta(&*sub_cow, depth + 2);
                }
            }
            FieldKind::List(SingularKind::Message(_)) => {
                if let ValueRef::List(list) = refl.get(fd) {
                    list.for_each(&mut |item| {
                        if let ValueRef::Message(sub_cow) = item
                            && let Some(cm) = build_reflect_value_schema_meta(&*sub_cow, depth + 2)
                        {
                            child = Some(merge_schema_meta(child.take(), cm));
                        }
                    });
                }
            }
            FieldKind::Map {
                value: SingularKind::Message(_),
                ..
            } => {
                if let ValueRef::Map(map) = refl.get(fd) {
                    map.for_each(&mut |_k, val| {
                        if let ValueRef::Message(sub_cow) = val
                            && let Some(cm) = build_reflect_value_schema_meta(&*sub_cow, depth + 2)
                        {
                            child = Some(merge_schema_meta(child.take(), cm));
                        }
                    });
                }
            }
            _ => {}
        }

        if let Some(c) = child {
            meta.children.insert(fnum, c);
        }
    }

    Some(meta)
}

/// Encodes any `buffa` [`Reflectable`] message directly into OmniBuf wire bytes.
///
/// Enabling `.generate_reflection(true)` (`ReflectMode::VTable`) in `buffa-build` allows this
/// encoder to read Rust struct fields in place with zero intermediate Protobuf buffers.
pub fn encode_buffa_reflect<M: Reflectable>(msg: &M, opts: EncodeOptions) -> Result<Vec<u8>> {
    let mut dst = Vec::with_capacity(128);
    encode_buffa_reflect_append(&mut dst, msg, opts)?;
    Ok(dst)
}

/// Appends the OmniBuf encoding of a `buffa` [`Reflectable`] message to `dst`.
pub fn encode_buffa_reflect_append<M: Reflectable>(
    dst: &mut Vec<u8>,
    msg: &M,
    opts: EncodeOptions,
) -> Result<()> {
    let refl = msg.reflect();
    encode_reflect_message_append(dst, &*refl, opts)
}

/// Encodes a `buffa` [`ReflectMessage`] (including [`DynamicMessage`]) into OmniBuf wire bytes.
pub fn encode_buffa_dynamic(msg: &DynamicMessage, opts: EncodeOptions) -> Result<Vec<u8>> {
    let mut dst = Vec::with_capacity(128);
    encode_reflect_message_append(&mut dst, msg, opts)?;
    Ok(dst)
}

/// Appends the OmniBuf encoding of any [`ReflectMessage`] to `dst`.
pub fn encode_reflect_message_append(
    dst: &mut Vec<u8>,
    refl: &dyn ReflectMessage,
    opts: EncodeOptions,
) -> Result<()> {
    let pool = refl.pool();
    let md = refl.message_descriptor();
    if opts.self_describing {
        let msg_idx = pool.message_index(md.full_name()).ok_or_else(|| {
            Error::serialize(format!(
                "message {:?} missing from its own DescriptorPool",
                md.full_name()
            ))
        })?;
        let mut active = HashSet::new();
        let (static_meta, cyclic) = build_buffa_schema_meta(pool, msg_idx, 1, &mut active);
        let meta = if cyclic {
            build_reflect_value_schema_meta(refl, 1).unwrap_or_default()
        } else {
            static_meta.unwrap_or_default()
        };
        meta.append_field0(dst);
    }
    encode_reflect_body(dst, refl, opts.deterministic)
}

/// Encodes any `buffa` [`BuffaMessage`] + [`MessageName`] using `pool` into OmniBuf wire bytes.
pub fn encode_buffa<M: BuffaMessage + MessageName>(
    msg: &M,
    pool: &Arc<DescriptorPool>,
    opts: EncodeOptions,
) -> Result<Vec<u8>> {
    let msg_idx = pool.message_index(M::FULL_NAME).ok_or_else(|| {
        Error::serialize(format!(
            "message {:?} not found in buffa DescriptorPool",
            M::FULL_NAME
        ))
    })?;
    encode_buffa_by_index(msg, pool, msg_idx, opts)
}

/// Encodes any `buffa` [`BuffaMessage`] using its explicit [`MessageIndex`] in `pool`.
pub fn encode_buffa_by_index<M: BuffaMessage>(
    msg: &M,
    pool: &Arc<DescriptorPool>,
    msg_idx: MessageIndex,
    opts: EncodeOptions,
) -> Result<Vec<u8>> {
    let proto_bytes = msg.encode_to_vec();
    let decode_opts = buffa::DecodeOptions::new().with_element_memory_limit(
        proto_bytes
            .len()
            .saturating_mul(64)
            .max(buffa::DEFAULT_ELEMENT_MEMORY_LIMIT),
    );
    let dyn_msg =
        DynamicMessage::decode_with_options(Arc::clone(pool), msg_idx, &proto_bytes, &decode_opts)
            .map_err(|e| Error::serialize(format!("buffa DynamicMessage decode failed: {e}")))?;
    encode_buffa_dynamic(&dyn_msg, opts)
}

/// Decodes OmniBuf wire bytes into a `buffa` [`DynamicMessage`], resetting absent fields.
pub fn decode_buffa_dynamic(data: &[u8], msg: &mut DynamicMessage) -> Result<()> {
    decode_buffa_dynamic_at_depth(data, msg, 0, false)
}

/// Decodes OmniBuf wire bytes into a `buffa` [`DynamicMessage`] while enforcing [`DecodeOptions`].
pub fn decode_buffa_dynamic_with_options(
    data: &[u8],
    msg: &mut DynamicMessage,
    opts: DecodeOptions,
) -> Result<()> {
    let schema_alloc = enforce_decode_options_with_schema_alloc(data, &opts)?;
    let _guard = AllocBudgetGuard::new(opts.max_alloc_bytes.saturating_sub(schema_alloc));
    decode_buffa_dynamic_at_depth(data, msg, 0, false)
}

/// Decodes OmniBuf wire bytes into any `buffa` [`BuffaMessage`] + [`MessageName`].
pub fn decode_buffa<M: BuffaMessage + MessageName + Default>(
    data: &[u8],
    pool: &Arc<DescriptorPool>,
) -> Result<M> {
    let msg_idx = pool.message_index(M::FULL_NAME).ok_or_else(|| {
        Error::parse(format!(
            "message {:?} not found in buffa DescriptorPool",
            M::FULL_NAME
        ))
    })?;
    decode_buffa_by_index(data, pool, msg_idx)
}

/// Decodes OmniBuf wire bytes into any `buffa` [`BuffaMessage`] + [`MessageName`] while enforcing [`DecodeOptions`].
pub fn decode_buffa_with_options<M: BuffaMessage + MessageName + Default>(
    data: &[u8],
    pool: &Arc<DescriptorPool>,
    opts: DecodeOptions,
) -> Result<M> {
    let schema_alloc = enforce_decode_options_with_schema_alloc(data, &opts)?;
    let _guard = AllocBudgetGuard::new(opts.max_alloc_bytes.saturating_sub(schema_alloc));
    decode_buffa(data, pool)
}

/// Decodes OmniBuf wire bytes into `dst` (`M: BuffaMessage + MessageName + Default`), resetting absent fields.
pub fn decode_buffa_into<M: BuffaMessage + MessageName + Default>(
    data: &[u8],
    pool: &Arc<DescriptorPool>,
    dst: &mut M,
) -> Result<()> {
    *dst = decode_buffa(data, pool)?;
    Ok(())
}

/// Decodes OmniBuf wire bytes into any `buffa` [`BuffaMessage`] using its explicit [`MessageIndex`].
pub fn decode_buffa_by_index<M: BuffaMessage + Default>(
    data: &[u8],
    pool: &Arc<DescriptorPool>,
    msg_idx: MessageIndex,
) -> Result<M> {
    let mut dyn_msg = DynamicMessage::new(Arc::clone(pool), msg_idx);
    decode_buffa_dynamic_at_depth(data, &mut dyn_msg, 0, false)?;
    let mut proto_buf = Vec::with_capacity(data.len() + 32);
    encode_buffa_dynamic_to_proto_bytes(&dyn_msg, &mut proto_buf)?;
    let buffa_opts = buffa::DecodeOptions::new().with_element_memory_limit(
        proto_buf
            .len()
            .saturating_mul(64)
            .max(buffa::DEFAULT_ELEMENT_MEMORY_LIMIT),
    );
    buffa_opts
        .decode_from_slice::<M>(&proto_buf)
        .map_err(|e| Error::parse(format!("buffa transcode decode failed: {e}")))
}

fn scalar_wire_type(st: ScalarType) -> u8 {
    match st {
        ScalarType::Uint32 | ScalarType::Uint64 => WIRE_UINT,
        ScalarType::Int32 | ScalarType::Sint32 | ScalarType::Int64 | ScalarType::Sint64 => {
            WIRE_SINT
        }
        ScalarType::Bool => WIRE_BOOL_FALSE,
        ScalarType::Fixed32 => WIRE_FIXED32,
        ScalarType::Fixed64 => WIRE_FIXED64,
        ScalarType::Sfixed32 => WIRE_SFIXED32,
        ScalarType::Sfixed64 => WIRE_SFIXED64,
        ScalarType::Float => WIRE_FLOAT32,
        ScalarType::Double => WIRE_FLOAT64,
        ScalarType::String => WIRE_STRING,
        ScalarType::Bytes => WIRE_BYTES,
    }
}

fn singular_wire_type(sk: SingularKind) -> u8 {
    match sk {
        SingularKind::Scalar(st) => scalar_wire_type(st),
        SingularKind::Enum(_) => WIRE_SINT,
        SingularKind::Message(_) => WIRE_SUB_MSG,
    }
}

fn append_value_ref_scalar_payload(
    dst: &mut Vec<u8>,
    sk: SingularKind,
    val: ValueRef<'_>,
) -> Result<()> {
    match (sk, val) {
        (SingularKind::Scalar(ScalarType::Bool), ValueRef::Bool(b)) => {
            dst.push(u8::from(b));
            Ok(())
        }
        (SingularKind::Scalar(ScalarType::Uint32), ValueRef::U32(v)) => {
            append_varint(dst, u64::from(v));
            Ok(())
        }
        (SingularKind::Scalar(ScalarType::Uint64), ValueRef::U64(v)) => {
            append_varint(dst, v);
            Ok(())
        }
        (SingularKind::Enum(_), ValueRef::EnumNumber(n)) => {
            append_varint(dst, encode_zigzag(i64::from(n)));
            Ok(())
        }
        (SingularKind::Scalar(ScalarType::Int32 | ScalarType::Sint32), ValueRef::I32(v)) => {
            append_varint(dst, encode_zigzag(i64::from(v)));
            Ok(())
        }
        (SingularKind::Scalar(ScalarType::Int64 | ScalarType::Sint64), ValueRef::I64(v)) => {
            append_varint(dst, encode_zigzag(v));
            Ok(())
        }
        (SingularKind::Scalar(ScalarType::String), ValueRef::String(s)) => {
            append_varint(dst, s.len() as u64);
            dst.extend_from_slice(s.as_bytes());
            Ok(())
        }
        (SingularKind::Scalar(ScalarType::Bytes), ValueRef::Bytes(b)) => {
            append_varint(dst, b.len() as u64);
            dst.extend_from_slice(b);
            Ok(())
        }
        (SingularKind::Scalar(ScalarType::Float), ValueRef::F32(f)) => {
            dst.extend_from_slice(&f.to_bits().to_le_bytes());
            Ok(())
        }
        (SingularKind::Scalar(ScalarType::Fixed32), ValueRef::U32(v)) => {
            dst.extend_from_slice(&v.to_le_bytes());
            Ok(())
        }
        (SingularKind::Scalar(ScalarType::Sfixed32), ValueRef::I32(v)) => {
            dst.extend_from_slice(&v.to_le_bytes());
            Ok(())
        }
        (SingularKind::Scalar(ScalarType::Double), ValueRef::F64(f)) => {
            dst.extend_from_slice(&f.to_bits().to_le_bytes());
            Ok(())
        }
        (SingularKind::Scalar(ScalarType::Fixed64), ValueRef::U64(v)) => {
            dst.extend_from_slice(&v.to_le_bytes());
            Ok(())
        }
        (SingularKind::Scalar(ScalarType::Sfixed64), ValueRef::I64(v)) => {
            dst.extend_from_slice(&v.to_le_bytes());
            Ok(())
        }
        (other_sk, other_val) => Err(Error::serialize(format!(
            "mismatched buffa ValueRef {other_val:?} for SingularKind {other_sk:?}"
        ))),
    }
}

fn append_map_key_ref_payload(
    dst: &mut Vec<u8>,
    key_st: ScalarType,
    key: MapKeyRef<'_>,
) -> Result<()> {
    match (key_st, key) {
        (ScalarType::Bool, MapKeyRef::Bool(b)) => {
            dst.push(u8::from(b));
            Ok(())
        }
        (ScalarType::Uint32, MapKeyRef::U32(v)) => {
            append_varint(dst, u64::from(v));
            Ok(())
        }
        (ScalarType::Uint64, MapKeyRef::U64(v)) => {
            append_varint(dst, v);
            Ok(())
        }
        (ScalarType::Int32 | ScalarType::Sint32, MapKeyRef::I32(v)) => {
            append_varint(dst, encode_zigzag(i64::from(v)));
            Ok(())
        }
        (ScalarType::Int64 | ScalarType::Sint64, MapKeyRef::I64(v)) => {
            append_varint(dst, encode_zigzag(v));
            Ok(())
        }
        (ScalarType::Fixed32, MapKeyRef::U32(v)) => {
            dst.extend_from_slice(&v.to_le_bytes());
            Ok(())
        }
        (ScalarType::Fixed64, MapKeyRef::U64(v)) => {
            dst.extend_from_slice(&v.to_le_bytes());
            Ok(())
        }
        (ScalarType::Sfixed32, MapKeyRef::I32(v)) => {
            dst.extend_from_slice(&v.to_le_bytes());
            Ok(())
        }
        (ScalarType::Sfixed64, MapKeyRef::I64(v)) => {
            dst.extend_from_slice(&v.to_le_bytes());
            Ok(())
        }
        (ScalarType::String, MapKeyRef::String(s)) => {
            append_varint(dst, s.len() as u64);
            dst.extend_from_slice(s.as_bytes());
            Ok(())
        }
        _ => Err(Error::serialize(format!(
            "unsupported buffa map key {key:?} for ScalarType {key_st:?}"
        ))),
    }
}

fn append_map_val_ref_payload(
    dst: &mut Vec<u8>,
    val_sk: SingularKind,
    val: ValueRef<'_>,
    deterministic: bool,
) -> Result<()> {
    match (val_sk, val) {
        (SingularKind::Message(_), ValueRef::Message(sub_cow)) => {
            let len_pos = dst.len();
            dst.extend_from_slice(&[0, 0]);
            encode_reflect_body(dst, &*sub_cow, deterministic)?;
            backpatch_container_len(dst, len_pos);
            Ok(())
        }
        (other_sk, other_val) => append_value_ref_scalar_payload(dst, other_sk, other_val),
    }
}

fn encode_reflect_body(
    dst: &mut Vec<u8>,
    refl: &dyn ReflectMessage,
    deterministic: bool,
) -> Result<()> {
    let pool = refl.pool();
    let md = refl.message_descriptor();

    if !md.extension_ranges().is_empty() {
        if let Some(msg_idx) = pool.message_index(md.full_name()) {
            for ext in pool.extensions_of(msg_idx) {
                if refl.has(ext.field()) {
                    return Err(Error::serialize(format!(
                        "proto2 extensions are not supported by OmniBuf: {}",
                        ext.field().name()
                    )));
                }
            }
        }
        for uf in refl.unknown_fields().iter() {
            if md.in_extension_range(uf.number) {
                return Err(Error::serialize(format!(
                    "proto2 extensions are not supported by OmniBuf (extension field #{})",
                    uf.number
                )));
            }
        }
    }

    let mut ordered_fields: Vec<&FieldDescriptor> = md.fields().iter().collect();
    ordered_fields.sort_by_key(|f| f.number());

    for fd in ordered_fields {
        if fd.is_delimited() {
            return Err(Error::serialize(format!(
                "delimited group fields are not supported by OmniBuf: {}.{}",
                md.full_name(),
                fd.name()
            )));
        }
        let fnum = fd.number();
        match fd.kind() {
            FieldKind::Map { key, value } => {
                let key_wt = scalar_wire_type(key);
                let val_wt = singular_wire_type(value);
                let ValueRef::Map(map) = refl.get(fd) else {
                    return Err(Error::serialize("expected ValueRef::Map for map field"));
                };
                append_tag(dst, fnum, WIRE_MAP);
                let len_pos = dst.len();
                dst.extend_from_slice(&[0, 0, key_wt, val_wt]);
                append_varint(dst, map.len() as u64);
                if deterministic && map.len() > 1 {
                    let mut entries: Vec<(MapKey, Value)> = Vec::with_capacity(map.len());
                    map.for_each(&mut |k, v| entries.push((k.to_owned(), v.to_owned())));
                    entries.sort_by(|a, b| a.0.cmp(&b.0));
                    for (k, v) in &entries {
                        append_map_key_ref_payload(dst, key, k.as_ref())?;
                        append_map_val_ref_payload(dst, value, v.as_ref(), deterministic)?;
                    }
                } else {
                    let mut err: Option<Error> = None;
                    map.for_each(&mut |k, v| {
                        if err.is_some() {
                            return;
                        }
                        if let Err(e) = append_map_key_ref_payload(dst, key, k) {
                            err = Some(e);
                            return;
                        }
                        if let Err(e) = append_map_val_ref_payload(dst, value, v, deterministic) {
                            err = Some(e);
                        }
                    });
                    if let Some(e) = err {
                        return Err(e);
                    }
                }
                backpatch_container_len(dst, len_pos);
            }
            FieldKind::List(elem_sk) => {
                let elem_wt = singular_wire_type(elem_sk);
                let ValueRef::List(list) = refl.get(fd) else {
                    return Err(Error::serialize("expected ValueRef::List for list field"));
                };
                append_tag(dst, fnum, WIRE_ARRAY);
                let len_pos = dst.len();
                dst.extend_from_slice(&[0, 0, elem_wt]);
                append_varint(dst, list.len() as u64);
                let mut err: Option<Error> = None;
                list.for_each(&mut |item| {
                    if err.is_some() {
                        return;
                    }
                    if let ValueRef::Message(sub_cow) = item {
                        let elem_pos = dst.len();
                        dst.extend_from_slice(&[0, 0]);
                        if let Err(e) = encode_reflect_body(dst, &*sub_cow, deterministic) {
                            err = Some(e);
                            return;
                        }
                        backpatch_container_len(dst, elem_pos);
                    } else if let Err(e) = append_value_ref_scalar_payload(dst, elem_sk, item) {
                        err = Some(e);
                    }
                });
                if let Some(e) = err {
                    return Err(e);
                }
                backpatch_container_len(dst, len_pos);
            }
            FieldKind::Singular(sk) => {
                if (fd.presence() == FieldPresence::Explicit
                    || matches!(sk, SingularKind::Message(_)))
                    && !refl.has(fd)
                {
                    continue;
                }
                let val = refl.get(fd);
                match (sk, val) {
                    (SingularKind::Message(_), ValueRef::Message(sub_cow)) => {
                        append_tag(dst, fnum, WIRE_SUB_MSG);
                        let len_pos = dst.len();
                        dst.extend_from_slice(&[0, 0]);
                        encode_reflect_body(dst, &*sub_cow, deterministic)?;
                        backpatch_container_len(dst, len_pos);
                    }
                    (SingularKind::Scalar(ScalarType::Bool), ValueRef::Bool(b)) => {
                        append_tag(dst, fnum, if b { WIRE_BOOL_TRUE } else { WIRE_BOOL_FALSE });
                    }
                    (sk_other, v_other) => {
                        let wt = singular_wire_type(sk_other);
                        append_tag(dst, fnum, wt);
                        append_value_ref_scalar_payload(dst, sk_other, v_other)?;
                    }
                }
            }
        }
    }

    Ok(())
}

fn decode_buffa_scalar_payload(
    data: &[u8],
    pos: usize,
    sk: SingularKind,
) -> Result<(Value, usize)> {
    match sk {
        SingularKind::Scalar(ScalarType::Bool) => {
            let b = *data
                .get(pos)
                .ok_or_else(|| Error::parse(format!("truncated bool at {pos}")))?;
            if b > 1 {
                return Err(Error::parse(format!("invalid bool byte {b} at {pos}")));
            }
            Ok((Value::Bool(b == 1), pos + 1))
        }
        SingularKind::Scalar(ScalarType::Uint32) => {
            let (v, vn) = decode_varint(
                data.get(pos..)
                    .ok_or_else(|| Error::parse("uint32 out of bounds"))?,
            )
            .ok_or_else(|| Error::parse(format!("truncated uint32 at {pos}")))?;
            Ok((Value::U32(v as u32), pos + vn))
        }
        SingularKind::Scalar(ScalarType::Uint64) => {
            let (v, vn) = decode_varint(
                data.get(pos..)
                    .ok_or_else(|| Error::parse("uint64 out of bounds"))?,
            )
            .ok_or_else(|| Error::parse(format!("truncated uint64 at {pos}")))?;
            Ok((Value::U64(v), pos + vn))
        }
        SingularKind::Enum(_) => {
            let (v, vn) = decode_varint(
                data.get(pos..)
                    .ok_or_else(|| Error::parse("enum out of bounds"))?,
            )
            .ok_or_else(|| Error::parse(format!("truncated enum at {pos}")))?;
            Ok((Value::EnumNumber(decode_zigzag(v) as i32), pos + vn))
        }
        SingularKind::Scalar(ScalarType::Int32 | ScalarType::Sint32) => {
            let (v, vn) = decode_varint(
                data.get(pos..)
                    .ok_or_else(|| Error::parse("int32 out of bounds"))?,
            )
            .ok_or_else(|| Error::parse(format!("truncated int32 at {pos}")))?;
            Ok((Value::I32(decode_zigzag(v) as i32), pos + vn))
        }
        SingularKind::Scalar(ScalarType::Int64 | ScalarType::Sint64) => {
            let (v, vn) = decode_varint(
                data.get(pos..)
                    .ok_or_else(|| Error::parse("int64 out of bounds"))?,
            )
            .ok_or_else(|| Error::parse(format!("truncated int64 at {pos}")))?;
            Ok((Value::I64(decode_zigzag(v)), pos + vn))
        }
        SingularKind::Scalar(ScalarType::String) => {
            let (s, next_pos) = read_str_slice(data, pos)?;
            Ok((Value::String(s.to_owned()), next_pos))
        }
        SingularKind::Scalar(ScalarType::Bytes) => {
            let (b, next_pos) = read_len_slice(data, pos, 0)?;
            Ok((Value::Bytes(b.to_vec()), next_pos))
        }
        SingularKind::Scalar(ScalarType::Float | ScalarType::Fixed32 | ScalarType::Sfixed32) => {
            let raw: [u8; 4] = data
                .get(pos..pos + 4)
                .ok_or_else(|| Error::parse(format!("truncated 32-bit scalar at {pos}")))?
                .try_into()
                .unwrap();
            let bits = u32::from_le_bytes(raw);
            let val = match sk {
                SingularKind::Scalar(ScalarType::Float) => Value::F32(f32::from_bits(bits)),
                SingularKind::Scalar(ScalarType::Fixed32) => Value::U32(bits),
                _ => Value::I32(bits as i32),
            };
            Ok((val, pos + 4))
        }
        SingularKind::Scalar(ScalarType::Double | ScalarType::Fixed64 | ScalarType::Sfixed64) => {
            let raw: [u8; 8] = data
                .get(pos..pos + 8)
                .ok_or_else(|| Error::parse(format!("truncated 64-bit scalar at {pos}")))?
                .try_into()
                .unwrap();
            let bits = u64::from_le_bytes(raw);
            let val = match sk {
                SingularKind::Scalar(ScalarType::Double) => Value::F64(f64::from_bits(bits)),
                SingularKind::Scalar(ScalarType::Fixed64) => Value::U64(bits),
                _ => Value::I64(bits as i64),
            };
            Ok((val, pos + 8))
        }
        SingularKind::Message(_) => Err(Error::parse(
            "unexpected SingularKind::Message in scalar decoder",
        )),
    }
}

fn buffa_value_to_map_key(val: Value) -> Result<MapKey> {
    match val {
        Value::Bool(b) => Ok(MapKey::Bool(b)),
        Value::I32(v) => Ok(MapKey::I32(v)),
        Value::I64(v) => Ok(MapKey::I64(v)),
        Value::U32(v) => Ok(MapKey::U32(v)),
        Value::U64(v) => Ok(MapKey::U64(v)),
        Value::String(s) => Ok(MapKey::String(s)),
        other => Err(Error::parse(format!("invalid buffa map key {other:?}"))),
    }
}

fn decode_buffa_dynamic_at_depth(
    data: &[u8],
    msg: &mut DynamicMessage,
    depth: usize,
    merge: bool,
) -> Result<()> {
    if depth > MAX_NESTING_DEPTH {
        return Err(Error::DepthLimitExceeded(depth));
    }
    let pool = Arc::clone(msg.pool());
    let msg_idx = msg.message_index();
    let md = pool.message(msg_idx);

    for fd in md.fields() {
        if fd.is_delimited() {
            return Err(Error::parse(format!(
                "delimited group fields are not supported by OmniBuf: {}.{}",
                md.full_name(),
                fd.name()
            )));
        }
    }

    if !merge {
        *msg = DynamicMessage::new(Arc::clone(&pool), msg_idx);
    }

    let n = data.len();
    let mut pos = 0usize;
    type PendingMapEntry<'a> = (&'a FieldDescriptor, Vec<(MapKey, Value)>);
    let mut pending_maps: BTreeMap<u32, PendingMapEntry<'_>> = BTreeMap::new();
    let mut pending_lists: BTreeMap<u32, (&FieldDescriptor, Vec<Value>)> = BTreeMap::new();
    let mut pending_submsgs: BTreeMap<u32, (&FieldDescriptor, DynamicMessage)> = BTreeMap::new();
    let mut touched_oneofs: Vec<u16> = Vec::new();

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

        if md.in_extension_range(fnum) && pool.extension_for(msg_idx, fnum).is_some() {
            return Err(Error::parse(format!(
                "proto2 extensions are not supported by OmniBuf (field #{fnum})"
            )));
        }

        let Some(fd) = md.field(fnum) else {
            pos = validate_value(data, pos, wt, depth)?;
            continue;
        };

        match fd.kind() {
            FieldKind::Map { key, value } => {
                if wt != WIRE_MAP {
                    pos = validate_value(data, pos, wt, depth)?;
                    continue;
                }
                if depth + 1 > MAX_NESTING_DEPTH {
                    return Err(Error::DepthLimitExceeded(depth + 1));
                }

                let exp_key_wt = scalar_wire_type(key);
                let exp_val_wt = singular_wire_type(value);
                let (body, next_pos) = read_len_slice(data, pos, 3)?;
                let (key_wt, val_wt, count, mut p) =
                    parse_map_header(body).ok_or_else(|| Error::parse("invalid WireMap header"))?;
                if key_wt != exp_key_wt || val_wt != exp_val_wt {
                    return Err(Error::parse("WireMap key/value wire type mismatch"));
                }
                charge_typed_alloc(count.saturating_mul(core::mem::size_of::<(MapKey, Value)>()))?;

                let (_, entries) = pending_maps.entry(fnum).or_insert_with(|| {
                    let seeded = if merge {
                        match msg.get(fd) {
                            ValueRef::Map(existing) => {
                                let mut prev = Vec::with_capacity(existing.len() + count.min(4096));
                                existing
                                    .for_each(&mut |k, v| prev.push((k.to_owned(), v.to_owned())));
                                prev
                            }
                            _ => Vec::with_capacity(count.min(4096)),
                        }
                    } else {
                        Vec::with_capacity(count.min(4096))
                    };
                    (fd, seeded)
                });
                entries.reserve(count.min(4096));

                for _ in 0..count {
                    let (kv, after_k) =
                        decode_buffa_scalar_payload(body, p, SingularKind::Scalar(key))?;
                    let mk = buffa_value_to_map_key(kv)?;
                    let (mv, after_v) = if let SingularKind::Message(sub_idx) = value {
                        let (sub_bytes, next_p) = read_len_slice(body, after_k, 0)?;
                        let mut sub_msg = DynamicMessage::new(Arc::clone(&pool), sub_idx);
                        decode_buffa_dynamic_at_depth(sub_bytes, &mut sub_msg, depth + 2, false)?;
                        (Value::Message(sub_msg), next_p)
                    } else {
                        decode_buffa_scalar_payload(body, after_k, value)?
                    };
                    entries.push((mk, mv));
                    p = after_v;
                }
                if p != body.len() {
                    return Err(Error::parse("WireMap trailing bytes"));
                }
                pos = next_pos;
            }
            FieldKind::List(elem_sk) => {
                if wt != WIRE_ARRAY {
                    pos = validate_value(data, pos, wt, depth)?;
                    continue;
                }
                if depth + 1 > MAX_NESTING_DEPTH {
                    return Err(Error::DepthLimitExceeded(depth + 1));
                }

                let exp_elem_wt = singular_wire_type(elem_sk);
                let (body, next_pos) = read_len_slice(data, pos, 2)?;
                let (elem_wt, count, mut p) = parse_array_header(body)
                    .ok_or_else(|| Error::parse("invalid WireArray header"))?;
                if elem_wt != exp_elem_wt {
                    return Err(Error::parse("WireArray element wire type mismatch"));
                }
                charge_typed_alloc(count.saturating_mul(core::mem::size_of::<Value>()))?;

                let (_, items) = pending_lists.entry(fnum).or_insert_with(|| {
                    let seeded = if merge {
                        match msg.get(fd) {
                            ValueRef::List(existing) => {
                                let mut prev = Vec::with_capacity(existing.len() + count.min(4096));
                                existing.for_each(&mut |v| prev.push(v.to_owned()));
                                prev
                            }
                            _ => Vec::with_capacity(count.min(4096)),
                        }
                    } else {
                        Vec::with_capacity(count.min(4096))
                    };
                    (fd, seeded)
                });
                items.reserve(count.min(4096));

                for _ in 0..count {
                    if let SingularKind::Message(sub_idx) = elem_sk {
                        let (sub_bytes, next_p) = read_len_slice(body, p, 0)?;
                        let mut sub_msg = DynamicMessage::new(Arc::clone(&pool), sub_idx);
                        decode_buffa_dynamic_at_depth(sub_bytes, &mut sub_msg, depth + 2, false)?;
                        items.push(Value::Message(sub_msg));
                        p = next_p;
                    } else {
                        let (v, next_p) = decode_buffa_scalar_payload(body, p, elem_sk)?;
                        items.push(v);
                        p = next_p;
                    }
                }
                if p != body.len() {
                    return Err(Error::parse("WireArray trailing bytes"));
                }
                pos = next_pos;
            }
            FieldKind::Singular(sk) => {
                if matches!(sk, SingularKind::Scalar(ScalarType::Bool)) {
                    if wt != WIRE_BOOL_FALSE && wt != WIRE_BOOL_TRUE {
                        pos = validate_value(data, pos, wt, depth)?;
                        continue;
                    }
                    if let Some(oneof_idx) = fd.oneof_index() {
                        pending_submsgs.retain(|_, (pfd, _)| pfd.oneof_index() != Some(oneof_idx));
                        if !touched_oneofs.contains(&oneof_idx) {
                            touched_oneofs.push(oneof_idx);
                        }
                    }
                    msg.set(fd, Value::Bool(wt == WIRE_BOOL_TRUE));
                    continue;
                }

                let exp_wt = singular_wire_type(sk);
                if wt != exp_wt {
                    pos = validate_value(data, pos, wt, depth)?;
                    continue;
                }

                if let SingularKind::Message(sub_idx) = sk {
                    let (sub_bytes, next_pos) = read_len_slice(data, pos, 0)?;
                    let oneof_idx = fd.oneof_index();
                    if let Some(oidx) = oneof_idx {
                        pending_submsgs.retain(|&pfnum, (pfd, _)| {
                            pfnum == fnum || pfd.oneof_index() != Some(oidx)
                        });
                    }
                    if let Some((_, sub_msg)) = pending_submsgs.get_mut(&fnum) {
                        decode_buffa_dynamic_at_depth(sub_bytes, sub_msg, depth + 1, true)?;
                    } else {
                        charge_typed_alloc(core::mem::size_of::<DynamicMessage>())?;
                        let merge_existing = merge
                            && msg.has(fd)
                            && oneof_idx.is_none_or(|oidx| !touched_oneofs.contains(&oidx));
                        if let Some(oidx) = oneof_idx
                            && !touched_oneofs.contains(&oidx)
                        {
                            touched_oneofs.push(oidx);
                        }
                        let mut sub_msg = if merge_existing {
                            match msg.get(fd) {
                                ValueRef::Message(cow) => cow.to_dynamic(),
                                _ => DynamicMessage::new(Arc::clone(&pool), sub_idx),
                            }
                        } else {
                            DynamicMessage::new(Arc::clone(&pool), sub_idx)
                        };
                        decode_buffa_dynamic_at_depth(
                            sub_bytes,
                            &mut sub_msg,
                            depth + 1,
                            merge_existing,
                        )?;
                        pending_submsgs.insert(fnum, (fd, sub_msg));
                    }
                    pos = next_pos;
                } else {
                    let (sv, next_pos) = decode_buffa_scalar_payload(data, pos, sk)?;
                    if let Some(oneof_idx) = fd.oneof_index() {
                        pending_submsgs.retain(|_, (pfd, _)| pfd.oneof_index() != Some(oneof_idx));
                        if !touched_oneofs.contains(&oneof_idx) {
                            touched_oneofs.push(oneof_idx);
                        }
                    }
                    msg.set(fd, sv);
                    pos = next_pos;
                }
            }
        }
    }

    for (_, (fd, sub_msg)) in pending_submsgs {
        msg.set(fd, Value::Message(sub_msg));
    }
    for (_, (fd, entries)) in pending_maps {
        msg.set(fd, Value::Map(MapValue::from_entries(entries)));
    }
    for (_, (fd, items)) in pending_lists {
        msg.set(fd, Value::List(items));
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

fn is_buffa_default_scalar(val: &ValueRef<'_>) -> bool {
    match *val {
        ValueRef::Bool(b) => !b,
        ValueRef::U32(v) => v == 0,
        ValueRef::U64(v) => v == 0,
        ValueRef::I32(v) => v == 0,
        ValueRef::I64(v) => v == 0,
        ValueRef::EnumNumber(n) => n == 0,
        ValueRef::F32(f) => f.to_bits() == 0,
        ValueRef::F64(f) => f.to_bits() == 0,
        ValueRef::String(s) => s.is_empty(),
        ValueRef::Bytes(b) => b.is_empty(),
        _ => false,
    }
}

fn write_buffa_proto_tagged_scalar(
    dst: &mut Vec<u8>,
    fnum: u32,
    sk: SingularKind,
    val: ValueRef<'_>,
) -> Result<()> {
    let f = u64::from(fnum);
    match (sk, val) {
        (SingularKind::Scalar(ScalarType::Bool), ValueRef::Bool(b)) => {
            write_proto_varint(dst, f << 3);
            dst.push(u8::from(b));
        }
        (SingularKind::Scalar(ScalarType::Uint32), ValueRef::U32(v)) => {
            write_proto_varint(dst, f << 3);
            write_proto_varint(dst, u64::from(v));
        }
        (SingularKind::Scalar(ScalarType::Uint64), ValueRef::U64(v)) => {
            write_proto_varint(dst, f << 3);
            write_proto_varint(dst, v);
        }
        (SingularKind::Scalar(ScalarType::Int32), ValueRef::I32(v)) => {
            write_proto_varint(dst, f << 3);
            write_proto_varint(dst, i64::from(v) as u64);
        }
        (SingularKind::Scalar(ScalarType::Int64), ValueRef::I64(v)) => {
            write_proto_varint(dst, f << 3);
            write_proto_varint(dst, v as u64);
        }
        (SingularKind::Enum(_), ValueRef::EnumNumber(n)) => {
            write_proto_varint(dst, f << 3);
            write_proto_varint(dst, i64::from(n) as u64);
        }
        (SingularKind::Scalar(ScalarType::Sint32), ValueRef::I32(v)) => {
            write_proto_varint(dst, f << 3);
            write_proto_varint(dst, write_proto_zigzag32(v));
        }
        (SingularKind::Scalar(ScalarType::Sint64), ValueRef::I64(v)) => {
            write_proto_varint(dst, f << 3);
            write_proto_varint(dst, write_proto_zigzag64(v));
        }
        (SingularKind::Scalar(ScalarType::Fixed32), ValueRef::U32(v)) => {
            write_proto_varint(dst, (f << 3) | 5);
            dst.extend_from_slice(&v.to_le_bytes());
        }
        (SingularKind::Scalar(ScalarType::Sfixed32), ValueRef::I32(v)) => {
            write_proto_varint(dst, (f << 3) | 5);
            dst.extend_from_slice(&v.to_le_bytes());
        }
        (SingularKind::Scalar(ScalarType::Float), ValueRef::F32(v)) => {
            write_proto_varint(dst, (f << 3) | 5);
            dst.extend_from_slice(&v.to_bits().to_le_bytes());
        }
        (SingularKind::Scalar(ScalarType::Fixed64), ValueRef::U64(v)) => {
            write_proto_varint(dst, (f << 3) | 1);
            dst.extend_from_slice(&v.to_le_bytes());
        }
        (SingularKind::Scalar(ScalarType::Sfixed64), ValueRef::I64(v)) => {
            write_proto_varint(dst, (f << 3) | 1);
            dst.extend_from_slice(&v.to_le_bytes());
        }
        (SingularKind::Scalar(ScalarType::Double), ValueRef::F64(v)) => {
            write_proto_varint(dst, (f << 3) | 1);
            dst.extend_from_slice(&v.to_bits().to_le_bytes());
        }
        (SingularKind::Scalar(ScalarType::String), ValueRef::String(s)) => {
            write_proto_varint(dst, (f << 3) | 2);
            write_proto_varint(dst, s.len() as u64);
            dst.extend_from_slice(s.as_bytes());
        }
        (SingularKind::Scalar(ScalarType::Bytes), ValueRef::Bytes(b)) => {
            write_proto_varint(dst, (f << 3) | 2);
            write_proto_varint(dst, b.len() as u64);
            dst.extend_from_slice(b);
        }
        (other_sk, other_val) => {
            return Err(Error::parse(format!(
                "unexpected ValueRef {other_val:?} for {other_sk:?} during buffa transcode"
            )));
        }
    }
    Ok(())
}

fn write_buffa_proto_map_key(
    dst: &mut Vec<u8>,
    key_st: ScalarType,
    key: MapKeyRef<'_>,
) -> Result<()> {
    let sk = SingularKind::Scalar(key_st);
    match key {
        MapKeyRef::Bool(b) => write_buffa_proto_tagged_scalar(dst, 1, sk, ValueRef::Bool(b)),
        MapKeyRef::I32(v) => write_buffa_proto_tagged_scalar(dst, 1, sk, ValueRef::I32(v)),
        MapKeyRef::I64(v) => write_buffa_proto_tagged_scalar(dst, 1, sk, ValueRef::I64(v)),
        MapKeyRef::U32(v) => write_buffa_proto_tagged_scalar(dst, 1, sk, ValueRef::U32(v)),
        MapKeyRef::U64(v) => write_buffa_proto_tagged_scalar(dst, 1, sk, ValueRef::U64(v)),
        MapKeyRef::String(s) => write_buffa_proto_tagged_scalar(dst, 1, sk, ValueRef::String(s)),
    }
}

fn encode_buffa_dynamic_to_proto_bytes(refl: &dyn ReflectMessage, dst: &mut Vec<u8>) -> Result<()> {
    let md = refl.message_descriptor();
    for fd in md.fields() {
        let fnum = fd.number();
        match fd.kind() {
            FieldKind::Map { key, value } => {
                let ValueRef::Map(map) = refl.get(fd) else {
                    continue;
                };
                let mut entry_buf = Vec::new();
                let mut err: Option<Error> = None;
                map.for_each(&mut |k, v| {
                    if err.is_some() {
                        return;
                    }
                    entry_buf.clear();
                    if let Err(e) = write_buffa_proto_map_key(&mut entry_buf, key, k) {
                        err = Some(e);
                        return;
                    }
                    if let ValueRef::Message(sub_cow) = v {
                        let mut sub_buf = Vec::new();
                        if let Err(e) = encode_buffa_dynamic_to_proto_bytes(&*sub_cow, &mut sub_buf)
                        {
                            err = Some(e);
                            return;
                        }
                        write_proto_varint(&mut entry_buf, (2 << 3) | 2);
                        write_proto_varint(&mut entry_buf, sub_buf.len() as u64);
                        entry_buf.extend_from_slice(&sub_buf);
                    } else if let Err(e) =
                        write_buffa_proto_tagged_scalar(&mut entry_buf, 2, value, v)
                    {
                        err = Some(e);
                        return;
                    }
                    write_proto_varint(dst, (u64::from(fnum) << 3) | 2);
                    write_proto_varint(dst, entry_buf.len() as u64);
                    dst.extend_from_slice(&entry_buf);
                });
                if let Some(e) = err {
                    return Err(e);
                }
            }
            FieldKind::List(elem_sk) => {
                let ValueRef::List(list) = refl.get(fd) else {
                    continue;
                };
                let mut sub_buf = Vec::new();
                let mut err: Option<Error> = None;
                list.for_each(&mut |item| {
                    if err.is_some() {
                        return;
                    }
                    if let ValueRef::Message(sub_cow) = item {
                        sub_buf.clear();
                        if let Err(e) = encode_buffa_dynamic_to_proto_bytes(&*sub_cow, &mut sub_buf)
                        {
                            err = Some(e);
                            return;
                        }
                        write_proto_varint(dst, (u64::from(fnum) << 3) | 2);
                        write_proto_varint(dst, sub_buf.len() as u64);
                        dst.extend_from_slice(&sub_buf);
                    } else if let Err(e) = write_buffa_proto_tagged_scalar(dst, fnum, elem_sk, item)
                    {
                        err = Some(e);
                    }
                });
                if let Some(e) = err {
                    return Err(e);
                }
            }
            FieldKind::Singular(sk) => {
                if fd.presence() == FieldPresence::Explicit
                    || matches!(sk, SingularKind::Message(_))
                {
                    if !refl.has(fd) {
                        continue;
                    }
                    let val = refl.get(fd);
                    if let ValueRef::Message(sub_cow) = val {
                        let mut sub_buf = Vec::new();
                        encode_buffa_dynamic_to_proto_bytes(&*sub_cow, &mut sub_buf)?;
                        write_proto_varint(dst, (u64::from(fnum) << 3) | 2);
                        write_proto_varint(dst, sub_buf.len() as u64);
                        dst.extend_from_slice(&sub_buf);
                    } else {
                        write_buffa_proto_tagged_scalar(dst, fnum, sk, val)?;
                    }
                } else {
                    let val = refl.get(fd);
                    if !is_buffa_default_scalar(&val) {
                        write_buffa_proto_tagged_scalar(dst, fnum, sk, val)?;
                    }
                }
            }
        }
    }
    Ok(())
}
