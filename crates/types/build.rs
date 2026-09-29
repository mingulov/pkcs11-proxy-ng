fn main() {
    // Step 7: `cargo kani` builds with `--cfg kani` (the proof module is
    // `#[cfg(kani)]`-gated). Declare the cfg name so stable/MSRV builds
    // stay warning-free under `-D warnings`. Done here — not via
    // `[lints.rust] unexpected_cfgs.check-cfg` in the manifest — because
    // cargo strips `check-cfg` when packaging, which trips the archive
    // manifest-identity gate (`normalized lints differ`).
    println!("cargo::rustc-check-cfg=cfg(kani)");
}
