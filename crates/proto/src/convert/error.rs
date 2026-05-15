// CkRv ↔ proto uint64 (trivial — just wrapping/unwrapping the u64)
// The proto layer uses raw u64 for ck_rv fields; CkRv is the typed newtype.
// No conversion module needed beyond this note: use `.0` to get u64 from CkRv,
// and `CkRv(value)` to construct from u64.
// This module exists as a placeholder for future conversion helpers.
