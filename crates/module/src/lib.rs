//! Shared PKCS#11 module-FFI facts: raw function-table acquisition,
//! function-list field-offset tables, and layout selection.
//!
//! Facts only — interface-*selection* policy (version fallback, provider
//! quirks) lives in the proxy backend; evidence policy (pointer→offset
//! mapping, provenance/alias analysis) lives in p11scope-discover. This
//! crate never calls `C_Initialize`. Design of record: the extraction spec
//! in the pkcs11-scope repository
//! (`docs/superpowers/specs/2026-08-10-module-crate-extraction-design.md`).

pub mod tables;

pub use tables::{
    FUNCTION_LIST_3_0_EXTRA_FIELDS, FUNCTION_LIST_3_2_EXTRA_FIELDS, FUNCTION_LIST_FIELDS, FnField,
    Surface, TableSet, detect_null_functions, read_fn_pointers, tables_for,
};
