use std::io::{self, Read, Write};
use std::process;

use prost::Message as _;
use prost_types::compiler::CodeGeneratorRequest;

fn main() {
    let mut input = Vec::new();
    if let Err(err) = io::stdin().read_to_end(&mut input) {
        eprintln!("protoc-gen-omnibuf-rs: failed to read stdin: {err}");
        process::exit(1);
    }

    let req = match CodeGeneratorRequest::decode(input.as_slice()) {
        Ok(req) => req,
        Err(err) => {
            eprintln!("protoc-gen-omnibuf-rs: failed to decode CodeGeneratorRequest: {err}");
            process::exit(1);
        }
    };

    let resp = protoc_gen_omnibuf_rs::generate(&req);
    let mut output = Vec::with_capacity(16 * 1024);
    if let Err(err) = resp.encode(&mut output) {
        eprintln!("protoc-gen-omnibuf-rs: failed to encode CodeGeneratorResponse: {err}");
        process::exit(1);
    }

    if let Err(err) = io::stdout().write_all(&output) {
        eprintln!("protoc-gen-omnibuf-rs: failed to write stdout: {err}");
        process::exit(1);
    }
}
