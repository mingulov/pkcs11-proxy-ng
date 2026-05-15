fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../../proto/pkcs11-proxy-ng/v1/service.proto");
    println!("cargo:rerun-if-changed=../../proto/pkcs11-proxy-ng/v1/types.proto");
    println!("cargo:rerun-if-changed=../../proto/pkcs11-proxy-ng/v1/mechanism_params.proto");

    tonic_prost_build::configure().build_server(true).build_client(true).compile_protos(
        &[
            "../../proto/pkcs11-proxy-ng/v1/service.proto",
            "../../proto/pkcs11-proxy-ng/v1/types.proto",
            "../../proto/pkcs11-proxy-ng/v1/mechanism_params.proto",
        ],
        &["../../proto"],
    )?;
    Ok(())
}
