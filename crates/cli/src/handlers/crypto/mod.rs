// ADR-0010 Scope-2 disposition (2026-10-25): these CLI handlers are
// the owner surface for the retained legacy per-function RPC family.
// They call the client convenience methods (`digest`/`encrypt`/
// `decrypt`/`sign`; `wrap_key` in `objects::key_ops`) because CLI
// output sizes are not known upfront and the legacy path sizes them
// daemon-side. Do not migrate individual handlers to Exact calls
// without an ADR-0010 note.
mod digest_cipher;
mod sign_verify;
#[cfg(test)]
mod tests;

pub(crate) use digest_cipher::{decrypt, digest, encrypt};
pub(crate) use sign_verify::{sign, verify};
