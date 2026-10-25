// ADR-0010 Scope-2 disposition (2026-10-25): the per-function
// convenience methods in this module (plus `wrap_key` /
// `get_operation_state` in `key_ops` and `encapsulate_key` in `kem`)
// are the retained legacy RPC family — daemon-sized outputs for
// CLI/compat callers. The shim never calls them; it uses the Exact
// family in `raw_output`. New byte-output functions extend the Exact
// family, not this one.
mod authenticated_typed;
mod authenticated_wrap;
mod combined;
mod digest_cipher;
mod message_crypto;
mod sign_verify;
mod verify_signature;
