//! Exact-output effects + init-negotiation version range (W1-L5-04, W1-L5-05).
//!
//! Both peers speak exact-output effects version 1 today. Gates accept the
//! compatibility RANGE `[MIN, MAX]` — never an equality literal — so a future
//! version bump degrades gracefully instead of breaking every exact-output op
//! on any single bump. Bump procedure (one place):
//! - additive vN+1 (old binaries ignore the new fields): raise `MAX` to N+1;
//!   peers negotiate the highest mutual version and the newer side emits
//!   effects the older side understands;
//! - breaking vN+1: raise BOTH `MIN` and `MAX`; mixed setups fail loudly at
//!   `Initialize` (W1-L5-05) instead of corrupting per-RPC effects.
//! - on the FIRST real bump (MAX > 1), plumb the agreed value to both peers:
//!   the client currently discards it (`?`-only at the `negotiate_init_version`
//!   call site in `crates/client/src/client/lifecycle.rs`) and the daemon
//!   checks overlap only (`.is_none()`-only in
//!   `crates/server/src/server/grpc_service/general/lifecycle.rs`). Discarding
//!   is correct while v1 is the only version; a second version needs the
//!   agreed value to select wire effects.
//!
//! `Initialize` exchanges `[min, max]` ranges; each side runs
//! [`negotiate_effects_version`]. Absent bounds (`None`) mean a legacy peer
//! that predates versioning, treated as v1-only so old/new binaries
//! interoperate in both directions.

/// Oldest exact-output effects version this binary interoperates with.
pub const EXACT_OUTPUT_EFFECTS_VERSION_MIN: u32 = 1;
/// Newest exact-output effects version this binary speaks.
pub const EXACT_OUTPUT_EFFECTS_VERSION_MAX: u32 = 1;

/// True when `v` lies within the supported compatibility range.
pub fn exact_output_effects_version_supported(v: u32) -> bool {
    (EXACT_OUTPUT_EFFECTS_VERSION_MIN..=EXACT_OUTPUT_EFFECTS_VERSION_MAX).contains(&v)
}

/// Highest mutually-supported version, or `None` when the ranges are
/// disjoint (fail loudly at init; never proceed with mismatched effects).
/// Each absent peer bound defaults to v1 independently (legacy peer =
/// v1-only), so a half-absent range with a real overlap still negotiates
/// the overlap's ceiling — e.g. `(None, Some(5))` against local `(1, 1)`
/// yields `Some(1)`. Ranges that are disjoint after defaulting — including
/// inverted ones like `(None, Some(0))` — fail closed to `None`.
pub fn negotiate_effects_version(
    local_min: u32,
    local_max: u32,
    peer_min: Option<u32>,
    peer_max: Option<u32>,
) -> Option<u32> {
    let peer_min = peer_min.unwrap_or(EXACT_OUTPUT_EFFECTS_VERSION_MIN);
    let peer_max = peer_max.unwrap_or(EXACT_OUTPUT_EFFECTS_VERSION_MIN);
    let floor = local_min.max(peer_min);
    let ceil = local_max.min(peer_max);
    (floor <= ceil).then_some(ceil)
}

/// Loud rejection for an out-of-range exact-effects version on a per-RPC
/// gate: `FAILED_PRECONDITION` naming the received version and the supported
/// range (one message shape for all six server gates).
pub fn exact_effects_version_rejected(received: u32) -> tonic::Status {
    tonic::Status::failed_precondition(format!(
        "exact output effects version {received} unsupported (supported {}..={})",
        EXACT_OUTPUT_EFFECTS_VERSION_MIN, EXACT_OUTPUT_EFFECTS_VERSION_MAX
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_accepts_only_the_defined_range() {
        assert!(!exact_output_effects_version_supported(0), "unversioned/legacy rejects");
        assert!(exact_output_effects_version_supported(1), "current version accepts");
        assert!(!exact_output_effects_version_supported(2), "beyond max rejects loudly");
        assert!(!exact_output_effects_version_supported(u32::MAX));
    }

    #[test]
    fn range_bounds_pin_v1_today() {
        // Structural pin: v1-only today; a future bump widens these in one
        // place and every gate + negotiation follows.
        assert_eq!(EXACT_OUTPUT_EFFECTS_VERSION_MIN, 1);
        assert_eq!(EXACT_OUTPUT_EFFECTS_VERSION_MAX, 1);
        assert!(exact_output_effects_version_supported(1));
    }

    #[test]
    fn negotiate_picks_highest_mutual_or_rejects_disjoint() {
        // Legacy peer (no version fields) is v1-only.
        assert_eq!(negotiate_effects_version(1, 1, None, None), Some(1));
        assert_eq!(
            negotiate_effects_version(1, 1, Some(1), Some(1)),
            Some(1),
            "matching ranges negotiate the shared version"
        );
        assert_eq!(
            negotiate_effects_version(1, 1, Some(1), Some(2)),
            Some(1),
            "future peer overlapping our range degrades to our max"
        );
        assert_eq!(
            negotiate_effects_version(1, 1, Some(2), Some(2)),
            None,
            "W1-L5-05: disjoint versions must fail loudly at init, not per-RPC"
        );
        assert_eq!(negotiate_effects_version(1, 1, Some(2), Some(3)), None);
        assert_eq!(
            negotiate_effects_version(1, 1, Some(0), Some(0)),
            None,
            "degenerate zero range never overlaps"
        );
        // Synthetic future locals (the helper takes bounds as params).
        assert_eq!(negotiate_effects_version(1, 2, Some(2), Some(2)), Some(2));
        assert_eq!(negotiate_effects_version(1, 2, Some(1), Some(1)), Some(1));
        assert_eq!(
            negotiate_effects_version(2, 2, Some(1), Some(1)),
            None,
            "breaking local bump rejects legacy peers loudly"
        );
        // Malformed peer ranges fail closed.
        assert_eq!(negotiate_effects_version(1, 1, Some(2), None), None);
        assert_eq!(negotiate_effects_version(1, 1, Some(2), Some(1)), None);
    }

    #[test]
    fn negotiate_half_absent_bounds_default_to_v1_independently() {
        // T29 M1: each absent bound defaults to v1 on its own; a real
        // overlap still negotiates (the old docstring wrongly claimed
        // every half-absent-nonzero range fails closed).
        assert_eq!(
            negotiate_effects_version(1, 1, None, Some(5)),
            Some(1),
            "half-absent peer bound with a real overlap negotiates the overlap"
        );
        assert_eq!(
            negotiate_effects_version(1, 1, None, Some(0)),
            None,
            "half-absent range disjoint after defaulting ([1,0] inverted) fails closed"
        );
    }

    #[test]
    fn rejected_status_is_failed_precondition_naming_the_range() {
        let status = exact_effects_version_rejected(2);
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert!(
            status.message().contains("1..=1") && status.message().contains('2'),
            "rejection must name the received version and the supported range, got: {}",
            status.message()
        );
    }
}
