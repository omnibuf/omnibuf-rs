mod generated;

use std::collections::HashMap;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::panic::{self, AssertUnwindSafe};
use std::process;

use omnibuf::wire::{WIRE_UINT, append_varint};
use omnibuf::{
    EncodeOptions, Error, Message, OmniBuf, buffa_codec, decode_blind, decode_blind_json, opaque,
    prost_codec,
};

pub mod proto_types {
    use std::sync::LazyLock;

    use prost_reflect::DescriptorPool;

    pub static DESCRIPTOR_POOL: LazyLock<DescriptorPool> = LazyLock::new(|| {
        DescriptorPool::decode(
            include_bytes!(concat!(env!("OUT_DIR"), "/file_descriptor_set.bin")).as_ref(),
        )
        .expect("valid embedded FileDescriptorSet")
    });

    pub mod omnibuf {
        pub mod bench {
            include!(concat!(env!("OUT_DIR"), "/omnibuf.bench.rs"));
        }
        pub mod conformance {
            include!(concat!(env!("OUT_DIR"), "/omnibuf.conformance.rs"));
        }
    }
}

pub mod buffa_types {
    use std::sync::{Arc, LazyLock};

    use buffa_descriptor::DescriptorPool;

    pub static DESCRIPTOR_POOL: LazyLock<Arc<DescriptorPool>> = LazyLock::new(|| {
        Arc::new(
            DescriptorPool::decode(
                include_bytes!(concat!(env!("OUT_DIR"), "/file_descriptor_set.bin")).as_ref(),
            )
            .expect("valid embedded buffa FileDescriptorSet"),
        )
    });

    pub static EDITIONS_DESCRIPTOR_POOL: LazyLock<Arc<DescriptorPool>> = LazyLock::new(|| {
        Arc::new(
            DescriptorPool::decode(
                include_bytes!(concat!(env!("OUT_DIR"), "/editions_descriptor_set.bin")).as_ref(),
            )
            .expect("valid embedded buffa Editions FileDescriptorSet"),
        )
    });

    include!(concat!(env!("OUT_DIR"), "/_buffa.rs"));
}

const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

const WIRE_FORMAT_JSON: u32 = 2;

const TIER_PLUGIN: u32 = 1;
const TIER_PROTOBUF_TYPES: u32 = 2;
const TIER_ANNOTATED_STRUCT: u32 = 3;
const TIER_BLIND: u32 = 4;

// ============================================================================
// IPC Framing Request & Response Messages
// ============================================================================

#[derive(Clone, Debug, Default, OmniBuf)]
#[omnibuf(name = "ConformanceRequest")]
struct ConformanceRequest {
    #[omnibuf(id = 1, name = "test_name")]
    test_name: String,
    #[omnibuf(id = 2, name = "message_type")]
    message_type: String,
    #[omnibuf(id = 3, name = "tier")]
    tier: u32,
    #[omnibuf(id = 4, name = "requested_output_format")]
    requested_output_format: u32,
    #[omnibuf(id = 5, name = "omnibuf_payload")]
    omnibuf_payload: Vec<u8>,
    #[omnibuf(id = 6, name = "json_payload")]
    json_payload: String,
    #[omnibuf(id = 7, name = "self_describing")]
    self_describing: bool,
    #[omnibuf(id = 8, name = "test_opaque_splice")]
    test_opaque_splice: bool,
    #[omnibuf(id = 9, name = "test_opaque_splice_shrink")]
    test_opaque_splice_shrink: bool,
}

#[derive(Clone, Debug, Default, OmniBuf)]
#[omnibuf(name = "ConformanceResponse")]
struct ConformanceResponse {
    #[omnibuf(id = 1, name = "parse_error", omitempty)]
    parse_error: String,
    #[omnibuf(id = 2, name = "serialize_error", omitempty)]
    serialize_error: String,
    #[omnibuf(id = 3, name = "runtime_error", omitempty)]
    runtime_error: String,
    #[omnibuf(id = 4, name = "skipped", omitempty)]
    skipped: String,
    #[omnibuf(id = 5, name = "omnibuf_payload", omitempty)]
    omnibuf_payload: Vec<u8>,
    #[omnibuf(id = 6, name = "json_payload", omitempty)]
    json_payload: String,
}

impl ConformanceResponse {
    fn parse_err(msg: impl Into<String>) -> Self {
        Self {
            parse_error: msg.into(),
            ..Self::default()
        }
    }

    fn serialize_err(msg: impl Into<String>) -> Self {
        Self {
            serialize_error: msg.into(),
            ..Self::default()
        }
    }

    fn runtime_err(msg: impl Into<String>) -> Self {
        Self {
            runtime_error: msg.into(),
            ..Self::default()
        }
    }

    fn skipped_reason(msg: impl Into<String>) -> Self {
        Self {
            skipped: msg.into(),
            ..Self::default()
        }
    }

    fn wire(bytes: Vec<u8>) -> Self {
        Self {
            omnibuf_payload: bytes,
            ..Self::default()
        }
    }

    fn json(s: String) -> Self {
        Self {
            json_payload: s,
            ..Self::default()
        }
    }
}

// ============================================================================
// Tier 3: Native Rust Annotated Structs (`#[derive(OmniBuf)]`)
// ============================================================================

#[derive(Clone, Debug, Default, PartialEq, OmniBuf)]
#[omnibuf(name = "Location")]
struct AnnotatedLocation {
    #[omnibuf(id = 1, name = "region")]
    region: String,
    #[omnibuf(id = 2, name = "datacenter")]
    datacenter: String,
    #[omnibuf(id = 3, name = "city")]
    city: String,
    #[omnibuf(id = 4, name = "rack")]
    rack: u32,
    #[omnibuf(id = 5, name = "latitude")]
    latitude: f32,
    #[omnibuf(id = 6, name = "longitude")]
    longitude: f32,
}

#[derive(Clone, Debug, Default, PartialEq, OmniBuf)]
#[omnibuf(name = "Neighbor")]
struct AnnotatedNeighbor {
    #[omnibuf(id = 1, name = "peer_asn")]
    peer_asn: u32,
    #[omnibuf(id = 2, name = "router")]
    router: String,
    #[omnibuf(id = 3, name = "latency_us")]
    latency_us: u32,
    #[omnibuf(id = 4, name = "established")]
    established: bool,
}

#[derive(Clone, Debug, Default, PartialEq, OmniBuf)]
#[omnibuf(name = "PeerUpdate")]
struct AnnotatedPeerUpdate {
    #[omnibuf(id = 1, name = "asn")]
    asn: u32,
    #[omnibuf(id = 2, name = "router_id")]
    router_id: String,
    #[omnibuf(id = 3, name = "active")]
    active: bool,
    #[omnibuf(id = 4, name = "uptime_sec")]
    uptime_sec: u64,
    #[omnibuf(id = 5, name = "rssi_dbm")]
    rssi_dbm: i32,
    #[omnibuf(id = 6, name = "cpu_load")]
    cpu_load: f64,
    #[omnibuf(id = 7, name = "tags")]
    tags: Vec<String>,
    #[omnibuf(id = 8, name = "prefixes")]
    prefixes: Vec<u32>,
    #[omnibuf(id = 9, name = "location")]
    location: AnnotatedLocation,
    #[omnibuf(id = 10, name = "neighbors")]
    neighbors: Vec<AnnotatedNeighbor>,
    #[omnibuf(id = 11, name = "sequence")]
    sequence: u64,
}

#[derive(Clone, Debug, Default, PartialEq, OmniBuf)]
#[omnibuf(name = "AllTypesSubMsg")]
struct AnnotatedAllTypesSubMsg {
    #[omnibuf(id = 1, name = "id")]
    id: u32,
    #[omnibuf(id = 2, name = "label")]
    label: String,
    #[omnibuf(id = 3, name = "flag")]
    flag: bool,
    #[omnibuf(id = 4, name = "score", wire = "sint")]
    score: i64,
}

#[derive(Clone, Debug, Default, PartialEq, OmniBuf)]
#[omnibuf(name = "TestAllTypes")]
struct AnnotatedTestAllTypes {
    #[omnibuf(id = 1, name = "f1_uint32")]
    f1_uint32: u32,
    #[omnibuf(id = 2, name = "f2_uint64")]
    f2_uint64: u64,
    #[omnibuf(id = 3, name = "f3_sint32", wire = "sint")]
    f3_sint32: i32,
    #[omnibuf(id = 4, name = "f4_sint64", wire = "sint")]
    f4_sint64: i64,
    #[omnibuf(id = 5, name = "f5_bool")]
    f5_bool: bool,
    #[omnibuf(id = 6, name = "f6_string")]
    f6_string: String,
    #[omnibuf(id = 7, name = "f7_bytes")]
    f7_bytes: Vec<u8>,
    #[omnibuf(id = 8, name = "f8_sub_msg")]
    f8_sub_msg: Option<AnnotatedAllTypesSubMsg>,
    #[omnibuf(id = 9, name = "f9_string_arr")]
    f9_string_arr: Vec<String>,
    #[omnibuf(id = 10, name = "f10_uint32_arr")]
    f10_uint32_arr: Vec<u32>,
    #[omnibuf(id = 11, name = "f11_sub_msg_arr")]
    f11_sub_msg_arr: Vec<AnnotatedAllTypesSubMsg>,
    #[omnibuf(id = 12, name = "f12_map_str_uint")]
    f12_map_str_uint: HashMap<String, u64>,
    #[omnibuf(id = 13, name = "f13_float32")]
    f13_float32: f32,
    #[omnibuf(id = 14, name = "f14_float64")]
    f14_float64: f64,
    #[omnibuf(id = 15, name = "f15_fixed32", wire = "fixed32")]
    f15_fixed32: u32,
    #[omnibuf(id = 16, name = "f16_fixed64", wire = "fixed64")]
    f16_fixed64: u64,
    #[omnibuf(id = 20, name = "f20_overflow_str")]
    f20_overflow_str: String,
}

#[allow(clippy::vec_box)]
#[derive(Clone, Debug, Default, PartialEq, OmniBuf)]
#[omnibuf(name = "TreeNode")]
struct AnnotatedTreeNode {
    #[omnibuf(id = 1, name = "id")]
    id: u32,
    #[omnibuf(id = 2, name = "name")]
    name: String,
    #[omnibuf(id = 3, name = "weight", wire = "sint")]
    weight: i64,
    #[omnibuf(id = 4, name = "primary")]
    primary: Option<Box<AnnotatedTreeNode>>,
    #[omnibuf(id = 5, name = "children")]
    children: Vec<AnnotatedTreeNode>,
    #[omnibuf(id = 6, name = "branches")]
    branches: Vec<Box<AnnotatedTreeNode>>,
    #[omnibuf(id = 7, name = "labels")]
    labels: HashMap<String, u64>,
}

#[derive(Clone, Debug, Default, PartialEq, OmniBuf)]
#[omnibuf(name = "NestedNIC")]
struct AnnotatedNestedNic {
    #[omnibuf(id = 1, name = "if_index")]
    if_index: u32,
    #[omnibuf(id = 2, name = "mac")]
    mac: String,
    #[omnibuf(id = 3, name = "ips")]
    ips: Vec<u32>,
}

#[derive(Clone, Debug, Default, PartialEq, OmniBuf)]
#[omnibuf(name = "NestedServer")]
struct AnnotatedNestedServer {
    #[omnibuf(id = 1, name = "server_id")]
    server_id: u32,
    #[omnibuf(id = 2, name = "hostname")]
    hostname: String,
    #[omnibuf(id = 3, name = "nics")]
    nics: Vec<AnnotatedNestedNic>,
}

#[derive(Clone, Debug, Default, PartialEq, OmniBuf)]
#[omnibuf(name = "NestedRack")]
struct AnnotatedNestedRack {
    #[omnibuf(id = 1, name = "rack_id")]
    rack_id: u32,
    #[omnibuf(id = 2, name = "zone")]
    zone: String,
    #[omnibuf(id = 3, name = "servers")]
    servers: Vec<AnnotatedNestedServer>,
}

#[derive(Clone, Debug, Default, PartialEq, OmniBuf)]
#[omnibuf(name = "NestedCluster")]
struct AnnotatedNestedCluster {
    #[omnibuf(id = 1, name = "cluster_name")]
    cluster_name: String,
    #[omnibuf(id = 2, name = "racks")]
    racks: Vec<AnnotatedNestedRack>,
    #[omnibuf(id = 3, name = "epoch")]
    epoch: u64,
}

// ============================================================================
// Main IPC Frame Loop
// ============================================================================

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = BufWriter::new(stdout.lock());

    loop {
        let req = match read_frame(&mut reader) {
            Ok(Some(req)) => req,
            Ok(None) => break,
            Err(err) => {
                eprintln!("conformance-rs read frame error: {err}");
                process::exit(1);
            }
        };

        let _ = (&req.test_name, &req.json_payload);

        let resp = match panic::catch_unwind(AssertUnwindSafe(|| handle_request(&req))) {
            Ok(r) => r,
            Err(payload) => {
                let msg = if let Some(s) = payload.downcast_ref::<&str>() {
                    (*s).to_owned()
                } else if let Some(s) = payload.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "panic during conformance request".to_owned()
                };
                ConformanceResponse::runtime_err(format!("panic: {msg}"))
            }
        };

        if let Err(err) = write_frame(&mut writer, &resp) {
            eprintln!("conformance-rs write frame error: {err}");
            process::exit(1);
        }
    }
}

fn read_frame<R: Read>(reader: &mut R) -> io::Result<Option<ConformanceRequest>> {
    let mut len_buf = [0u8; 4];
    let first = reader.read(&mut len_buf[..1])?;
    if first == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut len_buf[1..])?;
    let size = u32::from_le_bytes(len_buf) as usize;
    if size > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame size {size} exceeds limit {MAX_FRAME_BYTES}"),
        ));
    }
    let mut payload = vec![0u8; size];
    if size > 0 {
        reader.read_exact(&mut payload)?;
    }
    ConformanceRequest::from_omnibuf(&payload)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

fn write_frame<W: Write>(writer: &mut W, resp: &ConformanceResponse) -> io::Result<()> {
    let payload = resp
        .encode_omnibuf()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let len_bytes = (payload.len() as u32).to_le_bytes();
    writer.write_all(&len_bytes)?;
    if !payload.is_empty() {
        writer.write_all(&payload)?;
    }
    writer.flush()
}

fn handle_request(req: &ConformanceRequest) -> ConformanceResponse {
    match req.tier {
        TIER_BLIND => handle_blind_tier(req),
        TIER_PLUGIN => handle_plugin_tier(req),
        TIER_PROTOBUF_TYPES => handle_protobuf_types_tier(req),
        TIER_ANNOTATED_STRUCT => handle_annotated_struct_tier(req),
        other => ConformanceResponse::runtime_err(format!("unsupported tier: {other}")),
    }
}

// ============================================================================
// Tier 4: Blind Inspection
// ============================================================================

fn handle_blind_tier(req: &ConformanceRequest) -> ConformanceResponse {
    if req.requested_output_format == WIRE_FORMAT_JSON {
        return match decode_blind_json(&req.omnibuf_payload) {
            Ok(js) => ConformanceResponse::json(js),
            Err(Error::Serialize(_)) => ConformanceResponse::json("{}".to_owned()),
            Err(err) => ConformanceResponse::parse_err(err.to_string()),
        };
    }
    if let Err(err) = decode_blind(&req.omnibuf_payload) {
        return ConformanceResponse::parse_err(err.to_string());
    }
    ConformanceResponse::default()
}

// ============================================================================
// Tier 1: Plugin-Generated Code + Opaque Views & Splicing
// ============================================================================

macro_rules! handle_editions_plugin {
    (
        $req:expr,
        $mod_name:ident,
        $child:ident,
        $opaque_child:ident,
        $msg:ident,
        $borrowed:ident,
        $choice:ident,
        $choice_borrowed:ident
    ) => {{
        use crate::generated::$mod_name::{
            $borrowed, $child, $choice, $choice_borrowed, $msg, $opaque_child,
        };

        // Pre-populate every field with stale values to verify decode_omnibuf resets absent fields.
        let mut msg = $msg {
            explicit_int: Some(999),
            explicit_bool: Some(true),
            explicit_string: Some("stale-str".to_owned()),
            explicit_bytes: Some(vec![0xfe]),
            explicit_double: Some(123.5),
            status: Some(2),
            implicit_count: 999,
            implicit_flag: true,
            child: Some($child {
                id: Some(777),
                note: Some("stale-child".to_owned()),
            }),
            delimited_child: Some($child {
                id: Some(888),
                note: Some("stale-delim".to_owned()),
            }),
            packed_vals: vec![999],
            expanded_vals: vec![888],
            scores: [("stale".to_owned(), 999)].into_iter().collect(),
            choice: Some($choice::ChoiceInt(999)),
        };

        if let Err(err) = msg.unmarshal_omnibuf(&$req.omnibuf_payload) {
            return ConformanceResponse::parse_err(err.to_string());
        }

        // Verify zero-copy borrowed view parity.
        let borrowed = match $borrowed::from_omnibuf(&$req.omnibuf_payload) {
            Ok(b) => b,
            Err(err) => return ConformanceResponse::parse_err(err.to_string()),
        };
        let borrowed_choice_ok = match (&msg.choice, &borrowed.choice) {
            (None, None) => true,
            (Some($choice::ChoiceInt(a)), Some($choice_borrowed::ChoiceInt(b))) => a == b,
            (Some($choice::ChoiceText(a)), Some($choice_borrowed::ChoiceText(b))) => {
                a.as_str() == *b
            }
            (Some($choice::ChoiceFlag(a)), Some($choice_borrowed::ChoiceFlag(b))) => a == b,
            (Some($choice::ChoiceChild(a)), Some($choice_borrowed::ChoiceChild(b))) => {
                a.id == b.id && a.note.as_deref() == b.note
            }
            _ => false,
        };
        if borrowed.explicit_int != msg.explicit_int
            || borrowed.explicit_bool != msg.explicit_bool
            || borrowed.explicit_string != msg.explicit_string.as_deref()
            || borrowed.explicit_bytes != msg.explicit_bytes.as_deref()
            || borrowed.explicit_double.map(float64_canonical_bits)
                != msg.explicit_double.map(float64_canonical_bits)
            || borrowed.status != msg.status
            || borrowed.implicit_count != msg.implicit_count
            || borrowed.implicit_flag != msg.implicit_flag
            || borrowed.packed_vals != msg.packed_vals
            || borrowed.expanded_vals != msg.expanded_vals
            || borrowed.scores.len() != msg.scores.len()
            || !borrowed_choice_ok
        {
            return ConformanceResponse::runtime_err(
                "borrowed Editions view diverged from owned decoded struct",
            );
        }

        // Verify Opaque* child view parity (presence, getters, and clean marshal) for present children.
        let check_opaque_child = |c: &$child| -> Result<(), String> {
            let child_wire = c.marshal_omnibuf();
            let op = $opaque_child::try_new(&child_wire)
                .map_err(|e| format!("opaque child try_new failed: {e}"))?;
            if op.has_id() != c.id.is_some()
                || op.get_id() != c.id.unwrap_or_default()
                || op.has_note() != c.note.is_some()
                || op.get_note() != c.note.as_deref().unwrap_or("")
            {
                return Err("opaque Editions child getter mismatch with decoded struct".to_owned());
            }
            let reencoded = op
                .try_marshal()
                .map_err(|e| format!("opaque child try_marshal failed: {e}"))?;
            if reencoded != child_wire {
                return Err("opaque Editions child clean marshal diverged".to_owned());
            }
            Ok(())
        };
        if let Some(ref c) = msg.child
            && let Err(err) = check_opaque_child(c)
        {
            return ConformanceResponse::runtime_err(err);
        }
        if let Some(ref c) = msg.delimited_child
            && let Err(err) = check_opaque_child(c)
        {
            return ConformanceResponse::runtime_err(err);
        }
        if let Some($choice::ChoiceChild(ref c)) = msg.choice
            && let Err(err) = check_opaque_child(c)
        {
            return ConformanceResponse::runtime_err(err);
        }

        if $req.self_describing {
            return match msg.encode_omnibuf_with_options(EncodeOptions::self_describing()) {
                Ok(out) => ConformanceResponse::wire(out),
                Err(err) => ConformanceResponse::serialize_err(err.to_string()),
            };
        }
        ConformanceResponse::wire(msg.marshal_omnibuf())
    }};
}

fn handle_plugin_tier(req: &ConformanceRequest) -> ConformanceResponse {
    use generated::conformance_omnibuf::{AllTypesSubMsg, OpaqueTestAllTypes, TestAllTypes};
    use generated::peer_omnibuf::{Location, Neighbor, OpaquePeerUpdate, PeerUpdate};

    match req.message_type.as_str() {
        "omnibuf.bench.PeerUpdate" => {
            if req.test_opaque_splice || req.test_opaque_splice_shrink {
                let mut probe = OpaquePeerUpdate::new(&req.omnibuf_payload);
                probe.set_sequence(probe.get_sequence().wrapping_add(1));
                if let Err(err) = probe.try_marshal() {
                    return ConformanceResponse::parse_err(err.to_string());
                }
            }
            let mut msg = PeerUpdate {
                asn: 999_999,
                router_id: "stale-router".to_owned(),
                active: true,
                uptime_sec: 123,
                rssi_dbm: -42,
                cpu_load: 1.5,
                tags: vec!["stale-tag".to_owned()],
                prefixes: vec![999],
                location: Some(Location {
                    region: "stale".to_owned(),
                    datacenter: "stale-dc".to_owned(),
                    city: "stale-city".to_owned(),
                    rack: 999,
                    latitude: 1.0,
                    longitude: 2.0,
                }),
                neighbors: vec![Neighbor {
                    peer_asn: 999,
                    router: "stale-neighbor".to_owned(),
                    latency_us: 10,
                    established: true,
                }],
                sequence: 999_999,
            };
            if let Err(err) = msg.unmarshal_omnibuf(&req.omnibuf_payload) {
                return ConformanceResponse::parse_err(err.to_string());
            }
            if (req.test_opaque_splice || req.test_opaque_splice_shrink)
                && let Err(err) = check_splice_aliased_prefix(&req.omnibuf_payload)
            {
                return ConformanceResponse::runtime_err(err);
            }

            let mut op = OpaquePeerUpdate::new(&req.omnibuf_payload);
            let want_city = msg.location.as_ref().map_or("", |loc| loc.city.as_str());
            if op.get_asn() != msg.asn
                || op.get_router_id() != msg.router_id
                || op.get_active() != msg.active
                || op.get_uptime_sec() != msg.uptime_sec
                || op.get_rssi_dbm() != msg.rssi_dbm
                || op.get_cpu_load().to_bits() != msg.cpu_load.to_bits()
                || op.tags_len() != msg.tags.len()
                || op.prefixes_len() != msg.prefixes.len()
                || op.get_location().get_city() != want_city
                || op.neighbors_len() != msg.neighbors.len()
                || op.get_sequence() != msg.sequence
            {
                return ConformanceResponse::parse_err(
                    "opaque PeerUpdate getter mismatch with decoded struct",
                );
            }

            if req.test_opaque_splice {
                let next_active = !op.get_active();
                let next_seq = op.get_sequence().wrapping_add(1);
                op.set_asn(1_000_000);
                op.set_router_id("edge-rtr-fra01-".repeat(20));
                op.set_active(next_active);
                op.set_uptime_sec(u64::MAX);
                op.set_rssi_dbm(-1_000_000);
                op.set_cpu_load(99.875);
                op.set_tags(vec![
                    "tag-grow-a".to_owned(),
                    "tag-grow-b".to_owned(),
                    "long-tag-".repeat(20),
                ]);
                op.set_prefixes(vec![100_000, 200_000, 300_000, 400_000, 500_000, 600_000]);
                op.set_location(Some(Location {
                    region: "eu-central-grown".to_owned(),
                    datacenter: "fra-dc-".repeat(25),
                    city: "Berlin".to_owned(),
                    rack: 999_999,
                    latitude: 52.52,
                    longitude: 13.405,
                }));
                op.set_sequence(next_seq);
                return match op.try_marshal() {
                    Ok(out) => ConformanceResponse::wire(out),
                    Err(err) => ConformanceResponse::serialize_err(err.to_string()),
                };
            }

            if req.test_opaque_splice_shrink {
                op.set_asn(1);
                op.set_router_id("r");
                op.set_active(false);
                op.set_uptime_sec(5);
                op.set_rssi_dbm(-1);
                op.set_cpu_load(0.5);
                op.set_tags(vec!["t".to_owned()]);
                op.set_prefixes(vec![1]);
                op.set_location(Some(Location {
                    region: "r".to_owned(),
                    datacenter: "d".to_owned(),
                    city: "c".to_owned(),
                    rack: 1,
                    latitude: 1.0,
                    longitude: 2.0,
                }));
                op.set_sequence(2);
                return match op.try_marshal() {
                    Ok(out) => ConformanceResponse::wire(out),
                    Err(err) => ConformanceResponse::serialize_err(err.to_string()),
                };
            }

            if req.self_describing {
                return match msg.encode_omnibuf_with_options(EncodeOptions::self_describing()) {
                    Ok(out) => ConformanceResponse::wire(out),
                    Err(err) => ConformanceResponse::serialize_err(err.to_string()),
                };
            }
            ConformanceResponse::wire(msg.marshal_omnibuf())
        }

        "omnibuf.conformance.TestAllTypes" => {
            if req.test_opaque_splice || req.test_opaque_splice_shrink {
                let mut probe = OpaqueTestAllTypes::new(&req.omnibuf_payload);
                probe.set_f1_uint32(probe.get_f1_uint32().wrapping_add(1));
                if let Err(err) = probe.try_marshal() {
                    return ConformanceResponse::parse_err(err.to_string());
                }
            }
            let mut msg = TestAllTypes {
                f1_uint32: 999_999,
                f5_bool: true,
                f6_string: "stale-str".to_owned(),
                f7_bytes: vec![0xff],
                f8_sub_msg: Some(AllTypesSubMsg {
                    id: 999,
                    label: "stale-sub".to_owned(),
                    flag: true,
                    score: -999,
                }),
                f9_string_arr: vec!["stale".to_owned()],
                f10_uint32_arr: vec![999],
                f11_sub_msg_arr: vec![AllTypesSubMsg {
                    id: 999,
                    label: "stale-elem".to_owned(),
                    flag: false,
                    score: 0,
                }],
                f12_map_str_uint: [("stale".to_owned(), 999)].into_iter().collect(),
                f20_overflow_str: "stale-overflow".to_owned(),
                ..TestAllTypes::default()
            };

            if let Err(err) = msg.unmarshal_omnibuf(&req.omnibuf_payload) {
                return ConformanceResponse::parse_err(err.to_string());
            }
            if (req.test_opaque_splice || req.test_opaque_splice_shrink)
                && let Err(err) = check_splice_aliased_prefix(&req.omnibuf_payload)
            {
                return ConformanceResponse::runtime_err(err);
            }

            let mut op = OpaqueTestAllTypes::new(&req.omnibuf_payload);
            let _ = op.lookup_f12_map_str_uint("k");
            let default_sub = AllTypesSubMsg::default();
            let want_sub = msg.f8_sub_msg.as_ref().unwrap_or(&default_sub);
            let op_sub = op.get_f8_sub_msg();
            if op.get_f1_uint32() != msg.f1_uint32
                || op.get_f2_uint64() != msg.f2_uint64
                || op.get_f3_sint32() != msg.f3_sint32
                || op.get_f4_sint64() != msg.f4_sint64
                || op.get_f5_bool() != msg.f5_bool
                || op.get_f6_string() != msg.f6_string
                || op.get_f7_bytes() != msg.f7_bytes.as_slice()
                || op_sub.get_id() != want_sub.id
                || op_sub.get_label() != want_sub.label
                || op_sub.get_flag() != want_sub.flag
                || op_sub.get_score() != want_sub.score
                || op.f9_string_arr_len() != msg.f9_string_arr.len()
                || op.f10_uint32_arr_len() != msg.f10_uint32_arr.len()
                || op.f11_sub_msg_arr_len() != msg.f11_sub_msg_arr.len()
                || float32_canonical_bits(op.get_f13_float32())
                    != float32_canonical_bits(msg.f13_float32)
                || float64_canonical_bits(op.get_f14_float64())
                    != float64_canonical_bits(msg.f14_float64)
                || op.get_f15_fixed32() != msg.f15_fixed32
                || op.get_f16_fixed64() != msg.f16_fixed64
                || op.get_f20_overflow_str() != msg.f20_overflow_str
            {
                return ConformanceResponse::parse_err(
                    "opaque TestAllTypes getter mismatch with decoded struct",
                );
            }

            if req.test_opaque_splice {
                let next_bool = !op.get_f5_bool();
                op.set_f1_uint32(1_000_000);
                op.set_f2_uint64(u64::MAX);
                op.set_f3_sint32(-1_000_000);
                op.set_f4_sint64(i64::MIN);
                op.set_f5_bool(next_bool);
                op.set_f6_string("grown-str-".repeat(30));
                op.set_f7_bytes([0xabu8, 0xcdu8].repeat(130));
                op.set_f8_sub_msg(Some(AllTypesSubMsg {
                    id: 888_888,
                    label: "sub-grown-".repeat(20),
                    flag: true,
                    score: -999_999_999,
                }));
                op.set_f9_string_arr(vec![
                    "arr-grow-1".to_owned(),
                    "arr-grow-2".to_owned(),
                    "arr-grow-3-".repeat(15),
                ]);
                op.set_f10_uint32_arr(vec![100_000, 200_000, 300_000, 400_000, 500_000]);
                op.set_f11_sub_msg_arr(vec![
                    AllTypesSubMsg {
                        id: 100_001,
                        label: "elem0-".repeat(25),
                        flag: true,
                        score: -500_000,
                    },
                    AllTypesSubMsg {
                        id: 100_002,
                        label: "elem1-grown".to_owned(),
                        flag: false,
                        score: 500_000,
                    },
                ]);
                op.set_f12_map_str_uint(HashMap::from([
                    ("k1".to_owned(), 1_000_000),
                    ("k2".to_owned(), u64::MAX),
                    ("k3_long_key".to_owned(), 424_242),
                ]));
                op.set_f13_float32(-1234.5);
                op.set_f14_float64(std::f64::consts::PI);
                op.set_f15_fixed32(0xdead_beef);
                op.set_f16_fixed64(0xcafe_babe_dead_beef);
                op.set_f20_overflow_str("overflow20-".repeat(20));
                return match op.try_marshal() {
                    Ok(out) => ConformanceResponse::wire(out),
                    Err(err) => ConformanceResponse::serialize_err(err.to_string()),
                };
            }

            if req.test_opaque_splice_shrink {
                op.set_f1_uint32(1);
                op.set_f2_uint64(2);
                op.set_f3_sint32(-1);
                op.set_f4_sint64(-2);
                op.set_f5_bool(false);
                op.set_f6_string("s");
                op.set_f7_bytes(vec![0x01]);
                op.set_f8_sub_msg(Some(AllTypesSubMsg {
                    id: 1,
                    label: "x".to_owned(),
                    flag: false,
                    score: -1,
                }));
                op.set_f9_string_arr(vec!["a".to_owned()]);
                op.set_f10_uint32_arr(vec![7]);
                op.set_f11_sub_msg_arr(vec![AllTypesSubMsg {
                    id: 1,
                    label: "e".to_owned(),
                    flag: true,
                    score: 1,
                }]);
                op.set_f12_map_str_uint(HashMap::from([("k".to_owned(), 1)]));
                op.set_f13_float32(0.5);
                op.set_f14_float64(-0.25);
                op.set_f15_fixed32(7);
                op.set_f16_fixed64(9);
                op.set_f20_overflow_str("z");
                return match op.try_marshal() {
                    Ok(out) => ConformanceResponse::wire(out),
                    Err(err) => ConformanceResponse::serialize_err(err.to_string()),
                };
            }

            if req.self_describing {
                return match msg.encode_omnibuf_with_options(EncodeOptions::self_describing()) {
                    Ok(out) => ConformanceResponse::wire(out),
                    Err(err) => ConformanceResponse::serialize_err(err.to_string()),
                };
            }
            ConformanceResponse::wire(msg.marshal_omnibuf())
        }

        "omnibuf.conformance.TestEditions2023" => handle_editions_plugin!(
            req,
            editions_2023_omnibuf,
            Editions2023Child,
            OpaqueEditions2023Child,
            TestEditions2023,
            TestEditions2023Borrowed,
            TestEditions2023Choice,
            TestEditions2023ChoiceBorrowed
        ),

        "omnibuf.conformance.TestEditions2024" => handle_editions_plugin!(
            req,
            editions_2024_omnibuf,
            Editions2024Child,
            OpaqueEditions2024Child,
            TestEditions2024,
            TestEditions2024Borrowed,
            TestEditions2024Choice,
            TestEditions2024ChoiceBorrowed
        ),

        "omnibuf.conformance.TestEditions2026" => handle_editions_plugin!(
            req,
            editions_2026_omnibuf,
            Editions2026Child,
            OpaqueEditions2026Child,
            TestEditions2026,
            TestEditions2026Borrowed,
            TestEditions2026Choice,
            TestEditions2026ChoiceBorrowed
        ),

        _ => ConformanceResponse::skipped_reason(
            "plugin tier generated for PeerUpdate, TestAllTypes, and TestEditions2023/2024/2026",
        ),
    }
}

fn check_splice_aliased_prefix(packet: &[u8]) -> Result<(), String> {
    let append_dirty = |dst: &mut Vec<u8>, fnum: u16| {
        append_varint(dst, (u64::from(fnum) << 4) | u64::from(WIRE_UINT));
        append_varint(dst, 1u64 << 40);
    };
    let original = packet.to_vec();
    let spliced = opaque::splice_fields_vec(packet, 1 << 1, 2, append_dirty);

    for prefix_len in [0usize, 3, 32] {
        for extra_cap in [0usize, 512] {
            let prefix = vec![0xa5u8; prefix_len];
            let mut dst = Vec::with_capacity(prefix_len + packet.len() + extra_cap);
            dst.extend_from_slice(&prefix);

            let mut want = prefix;
            want.extend_from_slice(&spliced);

            opaque::splice_fields(&mut dst, packet, 1 << 1, 2, append_dirty);
            if dst != want {
                return Err(format!(
                    "opaque splice with {prefix_len}-byte prefix changed prefix or output"
                ));
            }
            if packet != original.as_slice() {
                return Err(format!(
                    "opaque splice with {prefix_len}-byte prefix modified source packet"
                ));
            }
        }
    }
    Ok(())
}

#[inline]
fn float32_canonical_bits(f: f32) -> u32 {
    if f.is_nan() { 0x7fc0_0000 } else { f.to_bits() }
}

#[inline]
fn float64_canonical_bits(f: f64) -> u64 {
    if f.is_nan() {
        0x7ff8_0000_0000_0000
    } else {
        f.to_bits()
    }
}

// ============================================================================
// Tier 2: Standard `prost` and `buffa` Protobuf Types
// ============================================================================

fn handle_protobuf_types_tier(req: &ConformanceRequest) -> ConformanceResponse {
    use buffa_types::omnibuf::bench as buffa_bench;
    use buffa_types::omnibuf::conformance as buffa_conf;
    use proto_types::omnibuf::bench::{Location, Neighbor, PeerUpdate};
    use proto_types::omnibuf::conformance::{AllTypesSubMsg, TestAllTypes};

    let opts = EncodeOptions {
        deterministic: true,
        self_describing: req.self_describing,
    };

    match req.message_type.as_str() {
        "omnibuf.bench.PeerUpdate" => {
            let mut msg = PeerUpdate {
                asn: 999_999,
                router_id: "stale-router".to_owned(),
                active: true,
                uptime_sec: 55,
                rssi_dbm: -12,
                cpu_load: 42.0,
                tags: vec!["stale".to_owned()],
                prefixes: vec![999],
                location: Some(Location {
                    region: "stale".to_owned(),
                    datacenter: "stale".to_owned(),
                    city: "stale".to_owned(),
                    rack: 999,
                    latitude: 1.0,
                    longitude: 2.0,
                }),
                neighbors: vec![Neighbor {
                    peer_asn: 999,
                    router: "stale".to_owned(),
                    latency_us: 1,
                    established: true,
                }],
                sequence: 999,
            };
            let mut buffa_msg = buffa_bench::PeerUpdate {
                asn: 999_999,
                router_id: "stale-router".to_owned(),
                active: true,
                uptime_sec: 55,
                rssi_dbm: -12,
                cpu_load: 42.0,
                tags: vec!["stale".to_owned()],
                prefixes: vec![999],
                location: buffa::MessageField::some(buffa_bench::Location {
                    region: "stale".to_owned(),
                    datacenter: "stale".to_owned(),
                    city: "stale".to_owned(),
                    rack: 999,
                    latitude: 1.0,
                    longitude: 2.0,
                    ..Default::default()
                }),
                neighbors: vec![buffa_bench::Neighbor {
                    peer_asn: 999,
                    router: "stale".to_owned(),
                    latency_us: 1,
                    established: true,
                    ..Default::default()
                }],
                sequence: 999,
                ..Default::default()
            };
            let mut buffa_derived = buffa_msg.clone();

            let mut reflected = msg.clone();
            if let Err(err) = prost_codec::decode_prost(&req.omnibuf_payload, &mut reflected) {
                return ConformanceResponse::parse_err(err.to_string());
            }
            if let Err(err) = buffa_codec::decode_buffa_into(
                &req.omnibuf_payload,
                &buffa_types::DESCRIPTOR_POOL,
                &mut buffa_msg,
            ) {
                return ConformanceResponse::parse_err(err.to_string());
            }
            if let Err(err) = buffa_derived.decode_omnibuf(&req.omnibuf_payload) {
                return ConformanceResponse::parse_err(err.to_string());
            }
            if let Err(err) = msg.decode_omnibuf(&req.omnibuf_payload) {
                return ConformanceResponse::parse_err(err.to_string());
            }

            let out = match msg.encode_omnibuf_with_options(opts) {
                Ok(b) => b,
                Err(err) => return ConformanceResponse::serialize_err(err.to_string()),
            };
            let buffa_refl_out = match buffa_codec::encode_buffa_reflect(&buffa_msg, opts) {
                Ok(b) => b,
                Err(err) => return ConformanceResponse::serialize_err(err.to_string()),
            };
            let buffa_pool_out =
                match buffa_codec::encode_buffa(&buffa_msg, &buffa_types::DESCRIPTOR_POOL, opts) {
                    Ok(b) => b,
                    Err(err) => return ConformanceResponse::serialize_err(err.to_string()),
                };
            let buffa_derive_out = match buffa_derived.encode_omnibuf_with_options(opts) {
                Ok(b) => b,
                Err(err) => return ConformanceResponse::serialize_err(err.to_string()),
            };
            if buffa_refl_out != out || buffa_pool_out != out || buffa_derive_out != out {
                return ConformanceResponse::runtime_err(
                    "buffa PeerUpdate OmniBuf output diverged from prost output",
                );
            }
            ConformanceResponse::wire(out)
        }

        "omnibuf.conformance.TestAllTypes" => {
            let mut msg = TestAllTypes {
                f1_uint32: 999_999,
                f5_bool: true,
                f6_string: "stale".to_owned(),
                f7_bytes: vec![0xaa],
                f8_sub_msg: Some(AllTypesSubMsg {
                    id: 999,
                    label: "stale".to_owned(),
                    flag: true,
                    score: -999,
                }),
                f9_string_arr: vec!["stale".to_owned()],
                f10_uint32_arr: vec![999],
                f11_sub_msg_arr: vec![AllTypesSubMsg {
                    id: 999,
                    label: "stale".to_owned(),
                    flag: false,
                    score: 0,
                }],
                f12_map_str_uint: [("stale".to_owned(), 999)].into_iter().collect(),
                f20_overflow_str: "stale".to_owned(),
                ..TestAllTypes::default()
            };
            let mut buffa_msg = buffa_conf::TestAllTypes {
                f1_uint32: 999_999,
                f5_bool: true,
                f6_string: "stale".to_owned(),
                f7_bytes: vec![0xaa],
                f8_sub_msg: buffa::MessageField::some(buffa_conf::AllTypesSubMsg {
                    id: 999,
                    label: "stale".to_owned(),
                    flag: true,
                    score: -999,
                    ..Default::default()
                }),
                f9_string_arr: vec!["stale".to_owned()],
                f10_uint32_arr: vec![999],
                f11_sub_msg_arr: vec![buffa_conf::AllTypesSubMsg {
                    id: 999,
                    label: "stale".to_owned(),
                    flag: false,
                    score: 0,
                    ..Default::default()
                }],
                f12_map_str_uint: [("stale".to_owned(), 999)].into_iter().collect(),
                f20_overflow_str: "stale".to_owned(),
                ..Default::default()
            };
            let mut buffa_derived = buffa_msg.clone();

            let mut reflected = msg.clone();
            if let Err(err) = prost_codec::decode_prost(&req.omnibuf_payload, &mut reflected) {
                return ConformanceResponse::parse_err(err.to_string());
            }
            if let Err(err) = buffa_codec::decode_buffa_into(
                &req.omnibuf_payload,
                &buffa_types::DESCRIPTOR_POOL,
                &mut buffa_msg,
            ) {
                return ConformanceResponse::parse_err(err.to_string());
            }
            if let Err(err) = buffa_derived.decode_omnibuf(&req.omnibuf_payload) {
                return ConformanceResponse::parse_err(err.to_string());
            }
            if let Err(err) = msg.decode_omnibuf(&req.omnibuf_payload) {
                return ConformanceResponse::parse_err(err.to_string());
            }

            let out = match msg.encode_omnibuf_with_options(opts) {
                Ok(b) => b,
                Err(err) => return ConformanceResponse::serialize_err(err.to_string()),
            };
            let buffa_refl_out = match buffa_codec::encode_buffa_reflect(&buffa_msg, opts) {
                Ok(b) => b,
                Err(err) => return ConformanceResponse::serialize_err(err.to_string()),
            };
            let buffa_pool_out =
                match buffa_codec::encode_buffa(&buffa_msg, &buffa_types::DESCRIPTOR_POOL, opts) {
                    Ok(b) => b,
                    Err(err) => return ConformanceResponse::serialize_err(err.to_string()),
                };
            let buffa_derive_out = match buffa_derived.encode_omnibuf_with_options(opts) {
                Ok(b) => b,
                Err(err) => return ConformanceResponse::serialize_err(err.to_string()),
            };
            if buffa_refl_out != out || buffa_pool_out != out || buffa_derive_out != out {
                return ConformanceResponse::runtime_err(
                    "buffa TestAllTypes OmniBuf output diverged from prost output",
                );
            }
            ConformanceResponse::wire(out)
        }

        "omnibuf.conformance.TestEditions2023"
        | "omnibuf.conformance.TestEditions2024"
        | "omnibuf.conformance.TestEditions2026" => {
            use std::sync::Arc;

            use buffa_descriptor::{DynamicMessage, ReflectMessageMut, Value};

            let pool = &*buffa_types::EDITIONS_DESCRIPTOR_POOL;
            let Some(msg_idx) = pool.message_index(req.message_type.as_str()) else {
                return ConformanceResponse::runtime_err(format!(
                    "editions message {:?} missing from buffa descriptor pool",
                    req.message_type
                ));
            };
            let md = pool.message(msg_idx);
            // Seed stale fields to confirm decode_buffa_dynamic resets absent fields cleanly.
            let mut dyn_msg = DynamicMessage::new(Arc::clone(pool), msg_idx);
            if let Some(fd) = md.field_by_name("explicit_int") {
                dyn_msg.set(fd, Value::I32(999));
            }
            if let Some(fd) = md.field_by_name("explicit_bool") {
                dyn_msg.set(fd, Value::Bool(true));
            }
            if let Some(fd) = md.field_by_name("implicit_count") {
                dyn_msg.set(fd, Value::I32(999));
            }
            if let Some(fd) = md.field_by_name("choice_int") {
                dyn_msg.set(fd, Value::I32(999));
            }

            if let Err(err) = buffa_codec::decode_buffa_dynamic(&req.omnibuf_payload, &mut dyn_msg)
            {
                return ConformanceResponse::parse_err(err.to_string());
            }
            match buffa_codec::encode_buffa_dynamic(&dyn_msg, opts) {
                Ok(out) => ConformanceResponse::wire(out),
                Err(err) => ConformanceResponse::serialize_err(err.to_string()),
            }
        }

        _ => ConformanceResponse::skipped_reason(
            "protobuf types tier generated for PeerUpdate, TestAllTypes, and TestEditions2023/2024/2026",
        ),
    }
}

// ============================================================================
// Tier 3: Plain Annotated Rust Structs (`#[derive(OmniBuf)]`)
// ============================================================================

fn handle_annotated_struct_tier(req: &ConformanceRequest) -> ConformanceResponse {
    let opts = EncodeOptions {
        deterministic: true,
        self_describing: req.self_describing,
    };

    match req.message_type.as_str() {
        "omnibuf.bench.PeerUpdate" => {
            let mut msg = AnnotatedPeerUpdate {
                asn: 999_999,
                router_id: "stale-router".to_owned(),
                active: true,
                uptime_sec: 123,
                rssi_dbm: -70,
                cpu_load: 12.5,
                tags: vec!["stale-tag".to_owned()],
                prefixes: vec![999],
                location: AnnotatedLocation {
                    region: "stale-region".to_owned(),
                    datacenter: "stale-dc".to_owned(),
                    city: "stale-city".to_owned(),
                    rack: 999,
                    latitude: 1.0,
                    longitude: 2.0,
                },
                neighbors: vec![AnnotatedNeighbor {
                    peer_asn: 999,
                    router: "stale-neighbor".to_owned(),
                    latency_us: 5,
                    established: true,
                }],
                sequence: 999_999,
            };
            round_trip_annotated(&req.omnibuf_payload, &mut msg, opts)
        }

        "omnibuf.conformance.TreeNode" => {
            let mut msg = AnnotatedTreeNode {
                id: 999,
                name: "stale-root".to_owned(),
                weight: -999,
                primary: Some(Box::new(AnnotatedTreeNode {
                    id: 888,
                    name: "stale-primary".to_owned(),
                    ..AnnotatedTreeNode::default()
                })),
                children: vec![AnnotatedTreeNode {
                    id: 777,
                    name: "stale-child".to_owned(),
                    ..AnnotatedTreeNode::default()
                }],
                branches: vec![Box::new(AnnotatedTreeNode {
                    id: 666,
                    name: "stale-branch".to_owned(),
                    ..AnnotatedTreeNode::default()
                })],
                labels: HashMap::from([("stale".to_owned(), 1)]),
            };
            round_trip_annotated(&req.omnibuf_payload, &mut msg, opts)
        }

        "omnibuf.conformance.NestedCluster" => {
            let mut msg = AnnotatedNestedCluster {
                cluster_name: "stale-cluster".to_owned(),
                racks: vec![AnnotatedNestedRack {
                    rack_id: 999,
                    zone: "stale-zone".to_owned(),
                    servers: vec![AnnotatedNestedServer {
                        server_id: 999,
                        hostname: "stale-host".to_owned(),
                        nics: vec![AnnotatedNestedNic {
                            if_index: 99,
                            mac: "ff:ff:ff:ff:ff:ff".to_owned(),
                            ips: vec![123],
                        }],
                    }],
                }],
                epoch: 999,
            };
            round_trip_annotated(&req.omnibuf_payload, &mut msg, opts)
        }

        _ => {
            let mut msg = AnnotatedTestAllTypes {
                f1_uint32: 999_999,
                f5_bool: true,
                f6_string: "stale-str".to_owned(),
                f7_bytes: vec![0xff],
                f8_sub_msg: Some(AnnotatedAllTypesSubMsg {
                    id: 999,
                    label: "stale-sub".to_owned(),
                    flag: true,
                    score: -999,
                }),
                f9_string_arr: vec!["stale".to_owned()],
                f10_uint32_arr: vec![999],
                f11_sub_msg_arr: vec![AnnotatedAllTypesSubMsg {
                    id: 999,
                    label: "stale-elem".to_owned(),
                    flag: false,
                    score: 0,
                }],
                f12_map_str_uint: [("stale".to_owned(), 999)].into_iter().collect(),
                f20_overflow_str: "stale-overflow".to_owned(),
                ..AnnotatedTestAllTypes::default()
            };
            round_trip_annotated(&req.omnibuf_payload, &mut msg, opts)
        }
    }
}

fn round_trip_annotated<M: Message>(
    payload: &[u8],
    msg: &mut M,
    opts: EncodeOptions,
) -> ConformanceResponse {
    if let Err(err) = msg.decode_omnibuf(payload) {
        return ConformanceResponse::parse_err(err.to_string());
    }
    match msg.encode_omnibuf_with_options(opts) {
        Ok(out) => ConformanceResponse::wire(out),
        Err(err) => ConformanceResponse::serialize_err(err.to_string()),
    }
}

#[cfg(test)]
mod buffa_integration_tests {
    use super::*;
    use buffa::MessageView as _;
    use omnibuf::{DecodeOptions, decode_blind_json, from_slice, to_vec_with_options};

    mod buffa_extra {
        include!(concat!(env!("OUT_DIR"), "/buffa_extra/mod.rs"));
    }

    #[test]
    fn buffa_tree_node_and_nested_cluster_roundtrip_and_self_describing_schema() {
        use buffa_extra::omnibuf::extra::{
            NestedCluster, NestedNIC, NestedRack, NestedServer, NodeRole, RouteEvent, TreeNode,
            TreeNodeView, route_event,
        };

        let pool = buffa_extra::omnibuf::extra::__buffa::reflect::descriptor_pool();

        // 1. Recursive TreeNode (tests boxed recursive MessageField<TreeNode, Box<TreeNode>>,
        //    children/branches Vec<TreeNode>, map<string, uint64>, and 1-level cycle leaf in Field #0)
        let tree = TreeNode {
            id: 1,
            name: "root-spine".to_owned(),
            weight: -500,
            primary: buffa::MessageField::some(TreeNode {
                id: 2,
                name: "primary-leaf".to_owned(),
                weight: 42,
                primary: buffa::MessageField::some(TreeNode {
                    id: 3,
                    name: "grandchild-leaf".to_owned(),
                    weight: -7,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            children: vec![TreeNode {
                id: 4,
                name: "child-a".to_owned(),
                weight: 100,
                ..Default::default()
            }],
            branches: vec![TreeNode {
                id: 5,
                name: "branch-b".to_owned(),
                weight: -99,
                ..Default::default()
            }],
            labels: [("tier".to_owned(), 1), ("asn".to_owned(), 64_512)]
                .into_iter()
                .collect(),
            ..Default::default()
        };

        let opts = EncodeOptions {
            deterministic: true,
            self_describing: true,
        };
        let wire_refl = buffa_codec::encode_buffa_reflect(&tree, opts).unwrap();
        let wire_pool = buffa_codec::encode_buffa(&tree, pool, opts).unwrap();
        let wire_derive = to_vec_with_options(&tree, opts).unwrap();
        assert_eq!(wire_refl, wire_pool);
        assert_eq!(wire_refl, wire_derive);

        let decoded_buffa: TreeNode = buffa_codec::decode_buffa(&wire_refl, pool).unwrap();
        assert_eq!(decoded_buffa, tree);
        let decoded_derive: TreeNode = from_slice(&wire_derive).unwrap();
        assert_eq!(decoded_derive, tree);

        // Verify Field #0 1-level cycle leaf preserves child field names in decode_blind_json!
        let blind_json = decode_blind_json(&wire_refl).unwrap();
        assert!(blind_json.contains("\"root-spine\""));
        assert!(blind_json.contains("\"primary-leaf\""));
        assert!(blind_json.contains("\"child-a\""));
        assert!(blind_json.contains("\"weight\":100"));

        // Also verify zero-copy buffa TreeNodeView works on native Protobuf bytes
        let pb_bytes = buffa::Message::encode_to_vec(&tree);
        let view = TreeNodeView::decode_view(&pb_bytes).unwrap();
        assert_eq!(view.name, "root-spine");
        assert_eq!(view.primary.name, "primary-leaf");

        // 2. 4-level NestedCluster round-trip across buffa_codec + #[derive(OmniBuf)]
        let cluster = NestedCluster {
            cluster_name: "fra-core-01".to_owned(),
            racks: vec![NestedRack {
                rack_id: 12,
                zone: "eu-central-1a".to_owned(),
                servers: vec![NestedServer {
                    server_id: 101,
                    hostname: "srv-fra-101".to_owned(),
                    nics: vec![NestedNIC {
                        if_index: 2,
                        mac: "00:1a:2b:3c:4d:5e".to_owned(),
                        ips: vec![0x0a00_0001, 0x0a00_0002],
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
            epoch: 1_700_000_000,
            ..Default::default()
        };

        let cluster_wire = buffa_codec::encode_buffa_reflect(&cluster, opts).unwrap();
        assert_eq!(cluster_wire, to_vec_with_options(&cluster, opts).unwrap());
        let cluster_rt: NestedCluster = buffa_codec::decode_buffa(&cluster_wire, pool).unwrap();
        assert_eq!(cluster_rt, cluster);

        // 3. RouteEvent with EnumValue<NodeRole> + Vec<EnumValue<NodeRole>> + oneof payload
        let ev_nic = RouteEvent {
            role: buffa::EnumValue::from(NodeRole::NODE_ROLE_SPINE),
            history: vec![
                buffa::EnumValue::from(NodeRole::NODE_ROLE_LEAF),
                buffa::EnumValue::Unknown(77),
            ],
            payload: Some(route_event::Payload::Nic(Box::new(NestedNIC {
                if_index: 9,
                mac: "aa:bb:cc:dd:ee:ff".to_owned(),
                ips: vec![127_000_001],
                ..Default::default()
            }))),
            ..Default::default()
        };
        let ev_wire = buffa_codec::encode_buffa_reflect(&ev_nic, opts).unwrap();
        assert_eq!(ev_wire, to_vec_with_options(&ev_nic, opts).unwrap());
        let ev_rt: RouteEvent = buffa_codec::decode_buffa(&ev_wire, pool).unwrap();
        assert_eq!(ev_rt, ev_nic);
        let ev_derive_rt: RouteEvent = from_slice(&ev_wire).unwrap();
        assert_eq!(ev_derive_rt, ev_nic);

        // Enforce DecodeOptions limits on buffa_codec::decode_buffa_with_options
        let tight = DecodeOptions {
            max_message_bytes: 4,
            ..DecodeOptions::default()
        };
        assert!(
            buffa_codec::decode_buffa_with_options::<NestedCluster>(&cluster_wire, pool, tight)
                .is_err()
        );
    }

    /// `OpaquePeerUpdate::marshal_append` and `try_marshal_append` must preserve an existing
    /// framing prefix (`[0xDE, 0xAD, 0xBE, 0xEF]`) in `dst` both when `dirty == 0` and when `dirty != 0`.
    #[test]
    fn opaque_peer_update_marshal_append_preserves_framing_prefix() {
        use crate::generated::peer_omnibuf;

        let orig = peer_omnibuf::PeerUpdate {
            asn: 64512,
            router_id: "edge-fra-01".to_owned(),
            sequence: 7,
            active: true,
            ..Default::default()
        };
        let raw = orig.marshal_omnibuf();
        let prefix = [0xDE, 0xAD, 0xBE, 0xEF];

        // 1. Clean (`dirty == 0`) marshal_append & try_marshal_append
        let clean_view = peer_omnibuf::OpaquePeerUpdate::new(&raw);

        let mut dst_clean = prefix.to_vec();
        clean_view.marshal_append(&mut dst_clean);
        assert!(
            dst_clean.starts_with(&prefix),
            "clean marshal_append wiped framing prefix: got {:?}",
            &dst_clean[..dst_clean.len().min(8)]
        );
        assert_eq!(
            peer_omnibuf::PeerUpdate::from_omnibuf(&dst_clean[4..]).unwrap(),
            orig
        );

        let mut dst_try_clean = prefix.to_vec();
        clean_view.try_marshal_append(&mut dst_try_clean).unwrap();
        assert!(
            dst_try_clean.starts_with(&prefix),
            "clean try_marshal_append wiped framing prefix: got {:?}",
            &dst_try_clean[..dst_try_clean.len().min(8)]
        );
        assert_eq!(
            peer_omnibuf::PeerUpdate::from_omnibuf(&dst_try_clean[4..]).unwrap(),
            orig
        );

        // 2. Dirty (`dirty != 0`) marshal_append & try_marshal_append
        let mut dirty_view = peer_omnibuf::OpaquePeerUpdate::new(&raw);
        dirty_view.set_sequence(42);

        let mut dst_dirty = prefix.to_vec();
        dirty_view.marshal_append(&mut dst_dirty);
        assert!(
            dst_dirty.starts_with(&prefix),
            "dirty marshal_append wiped framing prefix: got {:?}",
            &dst_dirty[..dst_dirty.len().min(8)]
        );
        let decoded_dirty = peer_omnibuf::PeerUpdate::from_omnibuf(&dst_dirty[4..]).unwrap();
        assert_eq!(decoded_dirty.sequence, 42);

        let mut dst_try_dirty = prefix.to_vec();
        dirty_view.try_marshal_append(&mut dst_try_dirty).unwrap();
        assert!(
            dst_try_dirty.starts_with(&prefix),
            "dirty try_marshal_append wiped framing prefix: got {:?}",
            &dst_try_dirty[..dst_try_dirty.len().min(8)]
        );
        let decoded_try_dirty =
            peer_omnibuf::PeerUpdate::from_omnibuf(&dst_try_dirty[4..]).unwrap();
        assert_eq!(decoded_try_dirty.sequence, 42);
    }
}
