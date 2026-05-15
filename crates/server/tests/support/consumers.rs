use std::path::{Path, PathBuf};

pub fn find_shim_library() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("PKCS11_PROXY_SHIM_LIB")
        && !path.is_empty()
    {
        let path = PathBuf::from(path);
        return path.exists().then_some(path);
    }

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = Path::new(manifest_dir).parent().and_then(|p| p.parent())?;

    let candidates = [
        workspace_root.join("target/debug/libpkcs11_proxy_ng_shim.so"),
        workspace_root.join("target/release/libpkcs11_proxy_ng_shim.so"),
    ];

    candidates.into_iter().find(|p| p.exists())
}
