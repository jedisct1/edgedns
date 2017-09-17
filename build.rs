extern crate prost_build;

fn main() {
    prost_build::compile_protos(&["src/edgedns-cli/edgedns-cli.proto"], &["src/edgedns-cli"])
        .unwrap();
}
