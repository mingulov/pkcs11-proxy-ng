// CK_ULONG-derived C types are u32 on narrow-CK_ULONG targets (i686, armv7,
// Windows x64). The wire newtypes are u64, so the server widens with `as u64` /
// `.into()`; that is a no-op only on 64-bit Unix. Allow both crate-wide so the
// same source compiles on every target (ADR-0011).
#![allow(clippy::unnecessary_cast, clippy::useless_conversion)]

pub mod config;
pub mod mechanism_registry_source;
pub mod server;

#[cfg(test)]
mod consistency_checks;
