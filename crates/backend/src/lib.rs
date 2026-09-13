// CK_ULONG-derived C types are u32 on narrow-CK_ULONG targets (i686, armv7,
// Windows x64) and u64 on 64-bit Unix. The wire newtypes are u64, so the FFI
// layer widens with `as u64` / `.into()`; that cast/conversion is a no-op (and
// thus "unnecessary"/"useless") only on 64-bit Unix. Allow both crate-wide so
// the same source compiles on every target (ADR-0011; needed for a 32-bit /
// Windows server proxying a narrow-CK_ULONG backend).
#![allow(clippy::unnecessary_cast, clippy::useless_conversion)]

pub mod ffi;
pub mod host_abi;
pub mod mock;
pub mod object_cleanup;
pub mod test_backend_3x;
pub mod traits;
pub use ffi::FfiBackend;
pub use mock::MockBackend;
pub use test_backend_3x::TestBackend3x;
pub use traits::Pkcs11Backend;
