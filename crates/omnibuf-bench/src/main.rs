use std::env;
use std::fs;
use std::hint::black_box;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use omnibuf::OmniBuf;
use prost::Message as _;
use serde::{Deserialize, Serialize};

mod generated {
    include!(concat!(env!("OUT_DIR"), "/peer_omnibuf.rs"));
}

mod pb {
    include!(concat!(env!("OUT_DIR"), "/omnibuf.bench.rs"));
}

#[derive(Clone, Debug, Default, PartialEq, OmniBuf, Serialize, Deserialize)]
struct DeriveLocation {
    #[omnibuf(id = 1)]
    region: String,
    #[omnibuf(id = 2)]
    datacenter: String,
    #[omnibuf(id = 3)]
    city: String,
    #[omnibuf(id = 4)]
    rack: u32,
    #[omnibuf(id = 5)]
    latitude: f32,
    #[omnibuf(id = 6)]
    longitude: f32,
}

#[derive(Clone, Debug, Default, PartialEq, OmniBuf, Serialize, Deserialize)]
struct DeriveNeighbor {
    #[omnibuf(id = 1)]
    peer_asn: u32,
    #[omnibuf(id = 2)]
    router: String,
    #[omnibuf(id = 3)]
    latency_us: u32,
    #[omnibuf(id = 4)]
    established: bool,
}

#[derive(Clone, Debug, Default, PartialEq, OmniBuf, Serialize, Deserialize)]
struct DerivePeerUpdate {
    #[omnibuf(id = 1)]
    asn: u32,
    #[omnibuf(id = 2)]
    router_id: String,
    #[omnibuf(id = 3)]
    active: bool,
    #[omnibuf(id = 4)]
    uptime_sec: u64,
    #[omnibuf(id = 5, wire = "sint")]
    rssi_dbm: i32,
    #[omnibuf(id = 6)]
    cpu_load: f64,
    #[omnibuf(id = 7)]
    tags: Vec<String>,
    #[omnibuf(id = 8)]
    prefixes: Vec<u32>,
    #[omnibuf(id = 9)]
    location: Option<DeriveLocation>,
    #[omnibuf(id = 10)]
    neighbors: Vec<DeriveNeighbor>,
    #[omnibuf(id = 11)]
    sequence: u64,
}

#[derive(Serialize)]
struct BenchmarkReport {
    language: &'static str,
    runtime: String,
    platform: &'static str,
    arch: &'static str,
    cpu: String,
    workload: &'static str,
    categories: Vec<BenchmarkCategory>,
}

#[derive(Serialize)]
struct BenchmarkCategory {
    id: &'static str,
    title: &'static str,
    unit: &'static str,
    results: Vec<BenchmarkResult>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct BenchmarkResult {
    name: &'static str,
    ns_per_op: u64,
    ops_per_sec: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    wire_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    highlight: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    baseline: Option<bool>,
}

fn sample_generated() -> generated::PeerUpdate {
    generated::PeerUpdate {
        asn: 64_512,
        router_id: "edge-rtr-fra01.core.backbone.net".to_owned(),
        active: true,
        uptime_sec: 1_849_203,
        rssi_dbm: -62,
        cpu_load: 0.42875,
        tags: vec![
            "tier1".to_owned(),
            "ebgp".to_owned(),
            "eu-central".to_owned(),
            "ixp-de-cix".to_owned(),
        ],
        prefixes: vec![
            167_772_160,
            172_032_000,
            3_232_235_520,
            2_886_729_728,
            134_744_072,
            134_743_040,
        ],
        location: Some(generated::Location {
            region: "eu-central-1".to_owned(),
            datacenter: "FRA-Equinix-FR5".to_owned(),
            city: "Frankfurt".to_owned(),
            rack: 42,
            latitude: 50.1109,
            longitude: 8.6821,
        }),
        neighbors: vec![
            generated::Neighbor {
                peer_asn: 3356,
                router: "ae0.fra1.level3.net".to_owned(),
                latency_us: 850,
                established: true,
            },
            generated::Neighbor {
                peer_asn: 1299,
                router: "ffm-b5-link.telia.net".to_owned(),
                latency_us: 920,
                established: true,
            },
            generated::Neighbor {
                peer_asn: 174,
                router: "be2040.ccr41.fra03.atlas.cogentco.com".to_owned(),
                latency_us: 1120,
                established: true,
            },
            generated::Neighbor {
                peer_asn: 2914,
                router: "ae-12.r24.frnkge08.de.bb.gin.ntt.net".to_owned(),
                latency_us: 980,
                established: false,
            },
        ],
        sequence: 9_876_543_210,
    }
}

fn sample_derive() -> DerivePeerUpdate {
    DerivePeerUpdate {
        asn: 64_512,
        router_id: "edge-rtr-fra01.core.backbone.net".to_owned(),
        active: true,
        uptime_sec: 1_849_203,
        rssi_dbm: -62,
        cpu_load: 0.42875,
        tags: vec![
            "tier1".to_owned(),
            "ebgp".to_owned(),
            "eu-central".to_owned(),
            "ixp-de-cix".to_owned(),
        ],
        prefixes: vec![
            167_772_160,
            172_032_000,
            3_232_235_520,
            2_886_729_728,
            134_744_072,
            134_743_040,
        ],
        location: Some(DeriveLocation {
            region: "eu-central-1".to_owned(),
            datacenter: "FRA-Equinix-FR5".to_owned(),
            city: "Frankfurt".to_owned(),
            rack: 42,
            latitude: 50.1109,
            longitude: 8.6821,
        }),
        neighbors: vec![
            DeriveNeighbor {
                peer_asn: 3356,
                router: "ae0.fra1.level3.net".to_owned(),
                latency_us: 850,
                established: true,
            },
            DeriveNeighbor {
                peer_asn: 1299,
                router: "ffm-b5-link.telia.net".to_owned(),
                latency_us: 920,
                established: true,
            },
            DeriveNeighbor {
                peer_asn: 174,
                router: "be2040.ccr41.fra03.atlas.cogentco.com".to_owned(),
                latency_us: 1120,
                established: true,
            },
            DeriveNeighbor {
                peer_asn: 2914,
                router: "ae-12.r24.frnkge08.de.bb.gin.ntt.net".to_owned(),
                latency_us: 980,
                established: false,
            },
        ],
        sequence: 9_876_543_210,
    }
}

fn sample_prost() -> pb::PeerUpdate {
    pb::PeerUpdate {
        asn: 64_512,
        router_id: "edge-rtr-fra01.core.backbone.net".to_owned(),
        active: true,
        uptime_sec: 1_849_203,
        rssi_dbm: -62,
        cpu_load: 0.42875,
        tags: vec![
            "tier1".to_owned(),
            "ebgp".to_owned(),
            "eu-central".to_owned(),
            "ixp-de-cix".to_owned(),
        ],
        prefixes: vec![
            167_772_160,
            172_032_000,
            3_232_235_520,
            2_886_729_728,
            134_744_072,
            134_743_040,
        ],
        location: Some(pb::Location {
            region: "eu-central-1".to_owned(),
            datacenter: "FRA-Equinix-FR5".to_owned(),
            city: "Frankfurt".to_owned(),
            rack: 42,
            latitude: 50.1109,
            longitude: 8.6821,
        }),
        neighbors: vec![
            pb::Neighbor {
                peer_asn: 3356,
                router: "ae0.fra1.level3.net".to_owned(),
                latency_us: 850,
                established: true,
            },
            pb::Neighbor {
                peer_asn: 1299,
                router: "ffm-b5-link.telia.net".to_owned(),
                latency_us: 920,
                established: true,
            },
            pb::Neighbor {
                peer_asn: 174,
                router: "be2040.ccr41.fra03.atlas.cogentco.com".to_owned(),
                latency_us: 1120,
                established: true,
            },
            pb::Neighbor {
                peer_asn: 2914,
                router: "ae-12.r24.frnkge08.de.bb.gin.ntt.net".to_owned(),
                latency_us: 980,
                established: false,
            },
        ],
        sequence: 9_876_543_210,
    }
}

fn measure<F>(
    name: &'static str,
    wire_bytes: Option<usize>,
    highlight: bool,
    baseline: bool,
    mut op: F,
) -> BenchmarkResult
where
    F: FnMut(),
{
    // 1. Warm up for 80ms and calibrate batch size.
    let warmup_start = Instant::now();
    let mut warmup_iters = 0u64;
    while warmup_start.elapsed() < Duration::from_millis(80) {
        for _ in 0..64 {
            op();
        }
        warmup_iters += 64;
    }
    let warmup_ns = warmup_start.elapsed().as_nanos() as f64;
    let est_ns = (warmup_ns / warmup_iters.max(1) as f64).max(1.0);
    let batch = ((2_000_000.0 / est_ns) as u64).clamp(16, 100_000);

    // 2. Run 7 independent 45ms trials and select the median ns/op.
    let mut samples = Vec::with_capacity(7);
    for _ in 0..7 {
        let trial_start = Instant::now();
        let mut iters = 0u64;
        while trial_start.elapsed() < Duration::from_millis(45) {
            for _ in 0..batch {
                op();
            }
            iters += batch;
        }
        let elapsed_ns = trial_start.elapsed().as_nanos() as f64;
        samples.push(elapsed_ns / iters as f64);
    }
    samples.sort_by(|a, b| a.total_cmp(b));
    let median_ns = samples[samples.len() / 2];

    let ns_per_op = median_ns.round().max(1.0) as u64;
    let ops_per_sec = (1_000_000_000.0 / median_ns).round() as u64;

    BenchmarkResult {
        name,
        ns_per_op,
        ops_per_sec,
        wire_bytes,
        highlight: highlight.then_some(true),
        baseline: baseline.then_some(true),
    }
}

fn detect_runtime_version() -> String {
    if let Ok(out) = Command::new("rustc").arg("--version").output()
        && out.status.success()
    {
        let raw = String::from_utf8_lossy(&out.stdout);
        let trimmed = raw.trim();
        let clean = trimmed
            .split_once(" (")
            .map_or(trimmed, |(prefix, _)| prefix);
        if !clean.is_empty() {
            return clean.to_owned();
        }
    }
    "rustc".to_owned()
}

fn detect_platform() -> &'static str {
    match env::consts::OS {
        "macos" => "darwin",
        other => other,
    }
}

fn detect_arch() -> &'static str {
    match env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        other => other,
    }
}

fn detect_cpu_model() -> String {
    if env::consts::OS == "macos"
        && let Ok(out) = Command::new("sysctl")
            .args(["-n", "machdep.cpu.brand_string"])
            .output()
        && out.status.success()
    {
        let brand = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if !brand.is_empty() {
            return brand;
        }
    }
    if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
        for line in cpuinfo.lines() {
            if let Some((k, v)) = line.split_once(':')
                && k.trim() == "model name"
            {
                let brand = v.trim();
                if !brand.is_empty() {
                    return brand.to_owned();
                }
            }
        }
    }
    "Unknown CPU".to_owned()
}

fn print_category(cat: &BenchmarkCategory) {
    let baseline_ns = cat
        .results
        .iter()
        .find(|r| r.baseline == Some(true))
        .map_or(1, |r| r.ns_per_op) as f64;

    println!("\n=== {} ===", cat.title);
    println!(
        "{:<30} {:>10} {:>14} {:>10} {:>10}",
        "Codec", "ns/op", "ops/sec", "wire (B)", "vs OmniBuf"
    );
    println!("{}", "-".repeat(78));
    for r in &cat.results {
        let wire_col = r
            .wire_bytes
            .map_or_else(|| "-".to_owned(), |b| b.to_string());
        let ratio = r.ns_per_op as f64 / baseline_ns;
        let rel = if r.baseline == Some(true) {
            "1.00x".to_owned()
        } else {
            format!("{ratio:.2}x")
        };
        println!(
            "{:<30} {:>10} {:>14} {:>10} {:>10}",
            r.name, r.ns_per_op, r.ops_per_sec, wire_col, rel
        );
    }
}

fn main() {
    let gen_msg = sample_generated();
    let derive_msg = sample_derive();
    let prost_msg = sample_prost();

    let omnibuf_bytes = gen_msg.marshal_omnibuf();
    let derive_bytes = omnibuf::to_vec(&derive_msg).expect("derive encode failed");
    let prost_bytes = prost_msg.encode_to_vec();
    let msgpack_bytes = rmp_serde::to_vec_named(&derive_msg).expect("msgpack encode failed");
    let json_bytes = serde_json::to_vec(&derive_msg).expect("json encode failed");

    // Canonical wire-size and round-trip assertions matching Go & TypeScript suites.
    assert_eq!(
        omnibuf_bytes.len(),
        366,
        "OmniBuf SamplePeerUpdate wire size must be 366 bytes"
    );
    assert_eq!(
        derive_bytes, omnibuf_bytes,
        "#[derive(OmniBuf)] wire output must match protoc-gen-omnibuf-rs output byte-for-byte"
    );
    assert_eq!(
        prost_bytes.len(),
        341,
        "Protobuf (prost) SamplePeerUpdate wire size must be 341 bytes"
    );

    let mut check_gen = generated::PeerUpdate::default();
    check_gen
        .unmarshal_omnibuf(&omnibuf_bytes)
        .expect("generated decode failed");
    assert_eq!(check_gen, gen_msg);

    let check_derive: DerivePeerUpdate =
        omnibuf::from_slice(&derive_bytes).expect("derive decode failed");
    assert_eq!(check_derive, derive_msg);

    let check_prost = pb::PeerUpdate::decode(prost_bytes.as_slice()).expect("prost decode failed");
    assert_eq!(check_prost, prost_msg);

    let check_mp: DerivePeerUpdate =
        rmp_serde::from_slice(&msgpack_bytes).expect("msgpack decode failed");
    assert_eq!(check_mp, derive_msg);

    let check_json: DerivePeerUpdate =
        serde_json::from_slice(&json_bytes).expect("json decode failed");
    assert_eq!(check_json, derive_msg);

    let check_op = generated::OpaquePeerUpdate::new(&omnibuf_bytes);
    assert_eq!(check_op.get_location().get_city(), "Frankfurt");
    let mut check_splice = generated::OpaquePeerUpdate::new(&omnibuf_bytes);
    check_splice.set_sequence(9_876_543_211);
    let spliced_bytes = check_splice.marshal();
    let mut check_mutated = generated::PeerUpdate::default();
    check_mutated
        .unmarshal_omnibuf(&spliced_bytes)
        .expect("spliced decode failed");
    assert_eq!(check_mutated.sequence, 9_876_543_211);
    assert_eq!(check_mutated.router_id, gen_msg.router_id);

    let runtime = detect_runtime_version();
    let platform = detect_platform();
    let arch = detect_arch();
    let cpu = detect_cpu_model();

    println!("OmniBuf Rust Benchmark Suite (PeerUpdate)");
    println!("Runtime: {runtime} | Platform: {platform}/{arch} | CPU: {cpu}");

    // 1. Full Message Encode Speed (PeerUpdate)
    let mut encode_results = vec![
        measure(
            "OmniBuf (Generated)",
            Some(omnibuf_bytes.len()),
            true,
            true,
            || {
                let out = black_box(&gen_msg).marshal_omnibuf();
                black_box(out);
            },
        ),
        measure(
            "OmniBuf (#[derive(OmniBuf)])",
            Some(derive_bytes.len()),
            true,
            false,
            || {
                let out = omnibuf::to_vec(black_box(&derive_msg)).unwrap();
                black_box(out);
            },
        ),
        measure(
            "prost (Protobuf)",
            Some(prost_bytes.len()),
            false,
            false,
            || {
                let out = black_box(&prost_msg).encode_to_vec();
                black_box(out);
            },
        ),
        measure(
            "rmp-serde (MessagePack)",
            Some(msgpack_bytes.len()),
            false,
            false,
            || {
                let out = rmp_serde::to_vec_named(black_box(&derive_msg)).unwrap();
                black_box(out);
            },
        ),
        measure("serde_json", Some(json_bytes.len()), false, false, || {
            let out = serde_json::to_vec(black_box(&derive_msg)).unwrap();
            black_box(out);
        }),
    ];
    encode_results.sort_by_key(|r| r.ns_per_op);

    // 2. Full Message Decode Speed (PeerUpdate)
    let mut decode_results = vec![
        measure("OmniBuf (Generated)", None, true, true, || {
            let mut msg = generated::PeerUpdate::default();
            msg.unmarshal_omnibuf(black_box(omnibuf_bytes.as_slice()))
                .unwrap();
            black_box(msg);
        }),
        measure("OmniBuf (#[derive(OmniBuf)])", None, true, false, || {
            let msg: DerivePeerUpdate =
                omnibuf::from_slice(black_box(omnibuf_bytes.as_slice())).unwrap();
            black_box(msg);
        }),
        measure("prost (Protobuf)", None, false, false, || {
            let msg = pb::PeerUpdate::decode(black_box(prost_bytes.as_slice())).unwrap();
            black_box(msg);
        }),
        measure("rmp-serde (MessagePack)", None, false, false, || {
            let msg: DerivePeerUpdate =
                rmp_serde::from_slice(black_box(msgpack_bytes.as_slice())).unwrap();
            black_box(msg);
        }),
        measure("serde_json", None, false, false, || {
            let msg: DerivePeerUpdate =
                serde_json::from_slice(black_box(json_bytes.as_slice())).unwrap();
            black_box(msg);
        }),
    ];
    decode_results.sort_by_key(|r| r.ns_per_op);

    // 3. Read a Single Nested Field (peer.location.city)
    let mut lookup_results = vec![
        measure("OmniBuf (Generated)", None, true, true, || {
            let view = generated::OpaquePeerUpdate::new(black_box(omnibuf_bytes.as_slice()));
            let loc = view.get_location();
            let city = loc.get_city();
            assert_eq!(city.len(), 9);
            black_box(city.as_ptr());
        }),
        measure("prost (Protobuf)", None, false, false, || {
            let msg = pb::PeerUpdate::decode(black_box(prost_bytes.as_slice())).unwrap();
            let city = msg.location.as_ref().unwrap().city.as_str();
            assert_eq!(city.len(), 9);
            black_box(city.as_ptr());
            black_box(&msg);
        }),
        measure("rmp-serde (MessagePack)", None, false, false, || {
            let msg: DerivePeerUpdate =
                rmp_serde::from_slice(black_box(msgpack_bytes.as_slice())).unwrap();
            let city = msg.location.as_ref().unwrap().city.as_str();
            assert_eq!(city.len(), 9);
            black_box(city.as_ptr());
            black_box(&msg);
        }),
        measure("serde_json", None, false, false, || {
            let msg: DerivePeerUpdate =
                serde_json::from_slice(black_box(json_bytes.as_slice())).unwrap();
            let city = msg.location.as_ref().unwrap().city.as_str();
            assert_eq!(city.len(), 9);
            black_box(city.as_ptr());
            black_box(&msg);
        }),
    ];
    lookup_results.sort_by_key(|r| r.ns_per_op);

    // 4. Selective Single-Field Mutation (peer.sequence)
    let mut mutate_results = vec![
        measure("OmniBuf (Generated)", None, true, true, || {
            let mut view = generated::OpaquePeerUpdate::new(black_box(omnibuf_bytes.as_slice()));
            view.set_sequence(black_box(9_876_543_211));
            let out = view.marshal();
            black_box(out);
        }),
        measure("prost (Protobuf)", None, false, false, || {
            let mut msg = pb::PeerUpdate::decode(black_box(prost_bytes.as_slice())).unwrap();
            msg.sequence = black_box(9_876_543_211);
            let out = msg.encode_to_vec();
            black_box(out);
        }),
        measure("rmp-serde (MessagePack)", None, false, false, || {
            let mut msg: DerivePeerUpdate =
                rmp_serde::from_slice(black_box(msgpack_bytes.as_slice())).unwrap();
            msg.sequence = black_box(9_876_543_211);
            let out = rmp_serde::to_vec_named(&msg).unwrap();
            black_box(out);
        }),
        measure("serde_json", None, false, false, || {
            let mut msg: DerivePeerUpdate =
                serde_json::from_slice(black_box(json_bytes.as_slice())).unwrap();
            msg.sequence = black_box(9_876_543_211);
            let out = serde_json::to_vec(&msg).unwrap();
            black_box(out);
        }),
    ];
    mutate_results.sort_by_key(|r| r.ns_per_op);

    let categories = vec![
        BenchmarkCategory {
            id: "encode",
            title: "Full Message Encode Speed (PeerUpdate)",
            unit: "ns",
            results: encode_results,
        },
        BenchmarkCategory {
            id: "decode",
            title: "Full Message Decode Speed (PeerUpdate)",
            unit: "ns",
            results: decode_results,
        },
        BenchmarkCategory {
            id: "lookup_city",
            title: "Read a Single Nested Field (peer.location.city)",
            unit: "ns",
            results: lookup_results,
        },
        BenchmarkCategory {
            id: "mutate_sequence",
            title: "Selective Single-Field Mutation (peer.sequence)",
            unit: "ns",
            results: mutate_results,
        },
    ];

    for cat in &categories {
        print_category(cat);
    }

    let report = BenchmarkReport {
        language: "rust",
        runtime,
        platform,
        arch,
        cpu,
        workload: "PeerUpdate",
        categories,
    };

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out_path = manifest_dir.join("../../testdata/benchmarks.json");
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).expect("failed to create testdata directory");
    }
    let mut json_text =
        serde_json::to_string_pretty(&report).expect("failed to serialize benchmark report");
    json_text.push('\n');
    fs::write(&out_path, json_text).expect("failed to write testdata/benchmarks.json");
    println!("\nWrote benchmark report to {}", out_path.display());
}
