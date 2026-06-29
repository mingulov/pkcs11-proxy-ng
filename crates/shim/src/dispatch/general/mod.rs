// CK_ULONG-derived C types (CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_SLOT_ID,
// CK_FLAGS, CK_MECHANISM_TYPE) are u32 on narrow-CK_ULONG targets (i686, armv7,
// Windows x64) and u64 on 64-bit Unix. The wire newtypes are u64, so the shim
// widens with `as u64` / `.into()` at construction; that cast/conversion is a
// no-op (and thus "unnecessary"/"useless") only on 64-bit Unix. Allow both
// module-wide for the dispatch layer so the same source compiles on every
// target. (ADR-0011.)
#![allow(clippy::unnecessary_cast, clippy::useless_conversion)]

mod admin;
mod async_ops;
mod authenticated_wrap;
mod combined;
mod digest_cipher;
mod helpers;
mod init_general;
mod kem;
mod key_ops;
mod message_crypto;
mod object;
mod session;
mod session_3x;
mod sign_verify;
mod slot;
mod state_ops;
mod unsupported;
mod verify_signature;

// Re-export all dispatch functions so `general::c_*` continues to work.
pub use admin::*;
pub use async_ops::*;
pub use authenticated_wrap::*;
pub use combined::*;
pub use digest_cipher::*;
pub(crate) use helpers::*;
pub use init_general::*;
pub use kem::*;
pub use key_ops::*;
pub use message_crypto::*;
pub use object::*;
pub use session::*;
pub use session_3x::*;
pub use sign_verify::*;
pub use slot::*;
pub use state_ops::*;
#[allow(unused_imports)]
pub use unsupported::*;
pub use verify_signature::*;
