use std::io::{self, Read, Write};
use std::process;

fn main() {
    let mut input = Vec::new();
    if let Err(err) = io::stdin().read_to_end(&mut input) {
        eprintln!("protoc-gen-omnibuf-rs: failed to read stdin: {err}");
        process::exit(1);
    }

    let output = match protoc_gen_omnibuf_rs::generate_request_bytes(&input) {
        Ok(output) => output,
        Err(err) => {
            eprintln!("protoc-gen-omnibuf-rs: invalid CodeGeneratorRequest: {err}");
            process::exit(1);
        }
    };

    if let Err(err) = io::stdout().write_all(&output) {
        eprintln!("protoc-gen-omnibuf-rs: failed to write stdout: {err}");
        process::exit(1);
    }
}
