use pkcs11_proxy_ng_types::CkRv;
use tonic::Code;

/// Map a gRPC transport failure to the most appropriate CK_RV (ADR-0003 §3).
pub fn grpc_status_to_ck_rv(code: Code, is_session_scoped: bool) -> CkRv {
    match code {
        Code::Unavailable => {
            if is_session_scoped {
                CkRv::DEVICE_ERROR
            } else {
                CkRv::TOKEN_NOT_PRESENT
            }
        }
        Code::DeadlineExceeded => CkRv::FUNCTION_FAILED,
        Code::Unauthenticated => CkRv::GENERAL_ERROR,
        Code::PermissionDenied => CkRv::GENERAL_ERROR,
        Code::InvalidArgument => CkRv::ARGUMENTS_BAD,
        Code::ResourceExhausted => CkRv::HOST_MEMORY,
        Code::Cancelled => CkRv::FUNCTION_CANCELED,
        Code::Internal => CkRv::GENERAL_ERROR,
        Code::FailedPrecondition => CkRv::GENERAL_ERROR,
        _ => CkRv::DEVICE_ERROR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_session_scoped_returns_device_error() {
        assert_eq!(grpc_status_to_ck_rv(Code::Unavailable, true), CkRv::DEVICE_ERROR);
    }

    #[test]
    fn unavailable_non_session_returns_token_not_present() {
        assert_eq!(grpc_status_to_ck_rv(Code::Unavailable, false), CkRv::TOKEN_NOT_PRESENT);
    }

    #[test]
    fn cancelled_returns_function_canceled() {
        assert_eq!(grpc_status_to_ck_rv(Code::Cancelled, false), CkRv::FUNCTION_CANCELED);
    }

    #[test]
    fn failed_precondition_returns_general_error() {
        assert_eq!(grpc_status_to_ck_rv(Code::FailedPrecondition, false), CkRv::GENERAL_ERROR);
    }

    #[test]
    fn unknown_code_returns_device_error() {
        assert_eq!(grpc_status_to_ck_rv(Code::DataLoss, false), CkRv::DEVICE_ERROR);
    }
}
