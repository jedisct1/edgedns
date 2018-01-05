extern crate prost_build;

fn main() {
    prost_build::compile_protos(
        &["../../edgedns-cli/edgedns-cli.proto"],
        &["../../edgedns-cli/"],
    ).expect("Unable to generate the protobuf definitions");
}
