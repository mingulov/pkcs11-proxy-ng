use std::sync::OnceLock;

use pkcs11_proxy_ng_types::CkRv;
use tonic::Code;

/// Categorises the PKCS#11 entry point that a gRPC error needs to be
/// mapped back to. Different entry points have different
/// spec-permitted `CK_RV` sets, so the mapping has to know which one
/// it is in. See PKCS#11 v3.0 §5 for the per-function "Returns" lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcKind {
    /// `C_Initialize` and `C_Finalize` — lifecycle entry points whose
    /// spec-permitted error set does NOT include `CKR_TOKEN_NOT_PRESENT`
    /// or `CKR_DEVICE_ERROR`. Failures map to `CKR_GENERAL_ERROR`
    /// (catastrophic) or `CKR_FUNCTION_FAILED` (transient).
    Lifecycle,
    /// `C_GetSlotList`, `C_GetSlotInfo`, `C_GetTokenInfo`,
    /// `C_GetMechanismList`, `C_GetMechanismInfo` — slot/token-scoped
    /// queries. `CKR_TOKEN_NOT_PRESENT` is permitted and is the most
    /// honest reflection of "the proxy can't reach the token".
    SlotOrToken,
    /// `C_OpenSession`, `C_Sign`, `C_Encrypt`, … — session-scoped
    /// operations. `CKR_DEVICE_ERROR` is permitted and conventional.
    Session,
}

/// Map a gRPC transport failure to the most appropriate CK_RV
/// (ADR-0003 §3), aware of the PKCS#11 entry point being invoked.
///
/// The `kind` parameter selects between the spec-permitted error sets
/// for lifecycle, slot/token-scoped, and session-scoped functions.
/// Without it, the mapping cannot honour PKCS#11 v3.0 §5.4's strict
/// `C_Initialize` returns list, which omits `CKR_TOKEN_NOT_PRESENT`.
pub fn grpc_status_to_ck_rv_kind(code: Code, kind: RpcKind) -> CkRv {
    match code {
        // Transport unavailability: pick the most honest spec-permitted
        // value for the entry point we are in.
        Code::Unavailable => match kind {
            RpcKind::Lifecycle => CkRv::GENERAL_ERROR,
            RpcKind::SlotOrToken => CkRv::TOKEN_NOT_PRESENT,
            RpcKind::Session => CkRv::DEVICE_ERROR,
        },
        // Timeout: function couldn't be performed; CKR_FUNCTION_FAILED
        // is in every entry point's spec-permitted set.
        Code::DeadlineExceeded => CkRv::FUNCTION_FAILED,
        Code::Unauthenticated => CkRv::GENERAL_ERROR,
        Code::PermissionDenied => CkRv::GENERAL_ERROR,
        Code::InvalidArgument => CkRv::ARGUMENTS_BAD,
        Code::ResourceExhausted => CkRv::HOST_MEMORY,
        // CKR_FUNCTION_CANCELED isn't in every spec-permitted set, so
        // for Lifecycle we fall back to CKR_FUNCTION_FAILED.
        Code::Cancelled => match kind {
            RpcKind::Lifecycle => CkRv::FUNCTION_FAILED,
            _ => CkRv::FUNCTION_CANCELED,
        },
        Code::Internal => CkRv::GENERAL_ERROR,
        Code::FailedPrecondition => CkRv::GENERAL_ERROR,
        _ => match kind {
            // CKR_DEVICE_ERROR isn't permitted from C_Initialize, fall
            // back to CKR_GENERAL_ERROR there.
            RpcKind::Lifecycle => CkRv::GENERAL_ERROR,
            _ => CkRv::DEVICE_ERROR,
        },
    }
}

/// Back-compat wrapper for callers that haven't been migrated to
/// pass `RpcKind` yet. `is_session_scoped = true` maps to
/// `RpcKind::Session`; `false` maps to `RpcKind::SlotOrToken` (the
/// historical default — see ADR-0003 §3).
///
/// New code should prefer [`grpc_status_to_ck_rv_kind`] so it can
/// correctly emit lifecycle-permitted CK_RVs from `C_Initialize` /
/// `C_Finalize`.
pub fn grpc_status_to_ck_rv(code: Code, is_session_scoped: bool) -> CkRv {
    let kind = if is_session_scoped { RpcKind::Session } else { RpcKind::SlotOrToken };
    grpc_status_to_ck_rv_kind(code, kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_session_scoped_returns_device_error() {
        assert_eq!(grpc_status_to_ck_rv(Code::Unavailable, true), CkRv::DEVICE_ERROR);
        assert_eq!(
            grpc_status_to_ck_rv_kind(Code::Unavailable, RpcKind::Session),
            CkRv::DEVICE_ERROR
        );
    }

    #[test]
    fn unavailable_slot_or_token_returns_token_not_present() {
        assert_eq!(
            grpc_status_to_ck_rv_kind(Code::Unavailable, RpcKind::SlotOrToken),
            CkRv::TOKEN_NOT_PRESENT
        );
        // Legacy wrapper preserves this for non-session callers.
        assert_eq!(grpc_status_to_ck_rv(Code::Unavailable, false), CkRv::TOKEN_NOT_PRESENT);
    }

    #[test]
    fn unavailable_lifecycle_returns_general_error_per_spec() {
        // PKCS#11 v3.0 §5.4 lists CKR_GENERAL_ERROR in C_Initialize's
        // permitted returns; CKR_TOKEN_NOT_PRESENT is NOT permitted.
        assert_eq!(
            grpc_status_to_ck_rv_kind(Code::Unavailable, RpcKind::Lifecycle),
            CkRv::GENERAL_ERROR
        );
    }

    #[test]
    fn cancelled_lifecycle_returns_function_failed_per_spec() {
        // CKR_FUNCTION_CANCELED isn't in C_Initialize's permitted set;
        // CKR_FUNCTION_FAILED is.
        assert_eq!(
            grpc_status_to_ck_rv_kind(Code::Cancelled, RpcKind::Lifecycle),
            CkRv::FUNCTION_FAILED
        );
    }

    #[test]
    fn cancelled_session_returns_function_canceled() {
        assert_eq!(
            grpc_status_to_ck_rv_kind(Code::Cancelled, RpcKind::Session),
            CkRv::FUNCTION_CANCELED
        );
        // Legacy wrapper preserves the historical mapping for session-
        // scoped callers.
        assert_eq!(grpc_status_to_ck_rv(Code::Cancelled, true), CkRv::FUNCTION_CANCELED);
    }

    #[test]
    fn failed_precondition_returns_general_error() {
        assert_eq!(grpc_status_to_ck_rv(Code::FailedPrecondition, false), CkRv::GENERAL_ERROR);
    }

    #[test]
    fn unknown_code_session_returns_device_error() {
        assert_eq!(grpc_status_to_ck_rv(Code::DataLoss, false), CkRv::DEVICE_ERROR);
    }

    #[test]
    fn unknown_code_lifecycle_returns_general_error() {
        assert_eq!(
            grpc_status_to_ck_rv_kind(Code::DataLoss, RpcKind::Lifecycle),
            CkRv::GENERAL_ERROR
        );
    }
}
