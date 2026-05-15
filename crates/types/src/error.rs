/// A PKCS#11 return value. Newtype over u64 for faithful wire representation.
/// Uses associated constants for known values; unknown/vendor values pass through.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct CkRv(pub u64);

macro_rules! ck_rv_table {
    ($($name:ident = $value:expr;)+) => {
        impl CkRv {
            $(
                pub const $name: Self = Self($value);
            )+

            /// Construct a vendor-defined return value in the PKCS#11 vendor range.
            pub const fn from_vendor(offset: u32) -> Self {
                Self(Self::VENDOR_DEFINED.0 | offset as u64)
            }

            pub const fn is_ok(self) -> bool {
                self.0 == Self::OK.0
            }

            pub const fn is_err(self) -> bool {
                self.0 != Self::OK.0
            }

            pub const fn is_vendor_defined(self) -> bool {
                (self.0 & Self::VENDOR_DEFINED.0) == Self::VENDOR_DEFINED.0
            }
        }

        impl std::fmt::Display for CkRv {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let name = match *self {
                    $(
                        Self::$name => concat!("CKR_", stringify!($name)),
                    )+
                    _ => "CKR_UNKNOWN",
                };
                write!(f, "{} (0x{:08x})", name, self.0)
            }
        }
    };
}

// Standard CKR_* values from the vendored OASIS PKCS#11 3.02 `pkcs11t.h`.
// These match the currently used `cryptoki-sys 0.5.x` bindings and keep the
// higher-level `pkcs11-types` layer independent from that crate.
ck_rv_table! {
    OK = 0x0000_0000;
    CANCEL = 0x0000_0001;
    HOST_MEMORY = 0x0000_0002;
    SLOT_ID_INVALID = 0x0000_0003;
    GENERAL_ERROR = 0x0000_0005;
    FUNCTION_FAILED = 0x0000_0006;
    ARGUMENTS_BAD = 0x0000_0007;
    NO_EVENT = 0x0000_0008;
    NEED_TO_CREATE_THREADS = 0x0000_0009;
    CANT_LOCK = 0x0000_000A;
    ATTRIBUTE_READ_ONLY = 0x0000_0010;
    ATTRIBUTE_SENSITIVE = 0x0000_0011;
    ATTRIBUTE_TYPE_INVALID = 0x0000_0012;
    ATTRIBUTE_VALUE_INVALID = 0x0000_0013;
    ACTION_PROHIBITED = 0x0000_001B;
    DATA_INVALID = 0x0000_0020;
    DATA_LEN_RANGE = 0x0000_0021;
    DEVICE_ERROR = 0x0000_0030;
    DEVICE_MEMORY = 0x0000_0031;
    DEVICE_REMOVED = 0x0000_0032;
    ENCRYPTED_DATA_INVALID = 0x0000_0040;
    ENCRYPTED_DATA_LEN_RANGE = 0x0000_0041;
    AEAD_DECRYPT_FAILED = 0x0000_0042;
    FUNCTION_CANCELED = 0x0000_0050;
    FUNCTION_NOT_PARALLEL = 0x0000_0051;
    FUNCTION_NOT_SUPPORTED = 0x0000_0054;
    KEY_HANDLE_INVALID = 0x0000_0060;
    KEY_SIZE_RANGE = 0x0000_0062;
    KEY_TYPE_INCONSISTENT = 0x0000_0063;
    KEY_NOT_NEEDED = 0x0000_0064;
    KEY_CHANGED = 0x0000_0065;
    KEY_NEEDED = 0x0000_0066;
    KEY_INDIGESTIBLE = 0x0000_0067;
    KEY_FUNCTION_NOT_PERMITTED = 0x0000_0068;
    KEY_NOT_WRAPPABLE = 0x0000_0069;
    KEY_UNEXTRACTABLE = 0x0000_006A;
    MECHANISM_INVALID = 0x0000_0070;
    MECHANISM_PARAM_INVALID = 0x0000_0071;
    OBJECT_HANDLE_INVALID = 0x0000_0082;
    OPERATION_ACTIVE = 0x0000_0090;
    OPERATION_NOT_INITIALIZED = 0x0000_0091;
    PIN_INCORRECT = 0x0000_00A0;
    PIN_INVALID = 0x0000_00A1;
    PIN_LEN_RANGE = 0x0000_00A2;
    PIN_EXPIRED = 0x0000_00A3;
    PIN_LOCKED = 0x0000_00A4;
    SESSION_CLOSED = 0x0000_00B0;
    SESSION_COUNT = 0x0000_00B1;
    SESSION_HANDLE_INVALID = 0x0000_00B3;
    SESSION_PARALLEL_NOT_SUPPORTED = 0x0000_00B4;
    SESSION_READ_ONLY = 0x0000_00B5;
    SESSION_EXISTS = 0x0000_00B6;
    SESSION_READ_ONLY_EXISTS = 0x0000_00B7;
    SESSION_READ_WRITE_SO_EXISTS = 0x0000_00B8;
    SIGNATURE_INVALID = 0x0000_00C0;
    SIGNATURE_LEN_RANGE = 0x0000_00C1;
    TEMPLATE_INCOMPLETE = 0x0000_00D0;
    TEMPLATE_INCONSISTENT = 0x0000_00D1;
    TOKEN_NOT_PRESENT = 0x0000_00E0;
    TOKEN_NOT_RECOGNIZED = 0x0000_00E1;
    TOKEN_WRITE_PROTECTED = 0x0000_00E2;
    UNWRAPPING_KEY_HANDLE_INVALID = 0x0000_00F0;
    UNWRAPPING_KEY_SIZE_RANGE = 0x0000_00F1;
    UNWRAPPING_KEY_TYPE_INCONSISTENT = 0x0000_00F2;
    USER_ALREADY_LOGGED_IN = 0x0000_0100;
    USER_NOT_LOGGED_IN = 0x0000_0101;
    USER_PIN_NOT_INITIALIZED = 0x0000_0102;
    USER_TYPE_INVALID = 0x0000_0103;
    USER_ANOTHER_ALREADY_LOGGED_IN = 0x0000_0104;
    USER_TOO_MANY_TYPES = 0x0000_0105;
    WRAPPED_KEY_INVALID = 0x0000_0110;
    WRAPPED_KEY_LEN_RANGE = 0x0000_0112;
    WRAPPING_KEY_HANDLE_INVALID = 0x0000_0113;
    WRAPPING_KEY_SIZE_RANGE = 0x0000_0114;
    WRAPPING_KEY_TYPE_INCONSISTENT = 0x0000_0115;
    RANDOM_SEED_NOT_SUPPORTED = 0x0000_0120;
    RANDOM_NO_RNG = 0x0000_0121;
    DOMAIN_PARAMS_INVALID = 0x0000_0130;
    CURVE_NOT_SUPPORTED = 0x0000_0140;
    BUFFER_TOO_SMALL = 0x0000_0150;
    SAVED_STATE_INVALID = 0x0000_0160;
    INFORMATION_SENSITIVE = 0x0000_0170;
    STATE_UNSAVEABLE = 0x0000_0180;
    CRYPTOKI_NOT_INITIALIZED = 0x0000_0190;
    CRYPTOKI_ALREADY_INITIALIZED = 0x0000_0191;
    MUTEX_BAD = 0x0000_01A0;
    MUTEX_NOT_LOCKED = 0x0000_01A1;
    NEW_PIN_MODE = 0x0000_01B0;
    NEXT_OTP = 0x0000_01B1;
    EXCEEDED_MAX_ITERATIONS = 0x0000_01B5;
    FIPS_SELF_TEST_FAILED = 0x0000_01B6;
    LIBRARY_LOAD_FAILED = 0x0000_01B7;
    PIN_TOO_WEAK = 0x0000_01B8;
    PUBLIC_KEY_INVALID = 0x0000_01B9;
    FUNCTION_REJECTED = 0x0000_0200;
    TOKEN_RESOURCE_EXCEEDED = 0x0000_0201;
    OPERATION_CANCEL_FAILED = 0x0000_0202;
    KEY_EXHAUSTED = 0x0000_0203;
    PENDING = 0x0000_0204;
    SESSION_ASYNC_NOT_SUPPORTED = 0x0000_0205;
    SEED_RANDOM_REQUIRED = 0x0000_0206;
    OPERATION_NOT_VALIDATED = 0x0000_0207;
    TOKEN_NOT_INITIALIZED = 0x0000_0208;
    PARAMETER_SET_NOT_SUPPORTED = 0x0000_0209;
    VENDOR_DEFINED = 0x8000_0000;
}

impl std::fmt::Debug for CkRv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CkRv({})", self)
    }
}

/// Result type for PKCS#11 operations. Ok(T) means CKR_OK; Err(CkRv) carries
/// the specific error code.
pub type CkResult<T> = Result<T, CkRv>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ck_rv_ok_value() {
        assert_eq!(CkRv::OK.0, 0x0000_0000);
    }

    #[test]
    fn ck_rv_is_ok() {
        assert!(CkRv::OK.is_ok());
        assert!(!CkRv::GENERAL_ERROR.is_ok());
    }

    #[test]
    fn ck_rv_display() {
        assert_eq!(format!("{}", CkRv::OK), "CKR_OK (0x00000000)");
        assert_eq!(format!("{}", CkRv::PENDING), "CKR_PENDING (0x00000204)");
        assert_eq!(format!("{}", CkRv::from_vendor(0x42)), "CKR_UNKNOWN (0x80000042)");
    }

    #[test]
    fn ck_rv_vendor_helpers() {
        assert!(CkRv::VENDOR_DEFINED.is_vendor_defined());
        assert!(CkRv::from_vendor(0x42).is_vendor_defined());
        assert!(!CkRv::OK.is_vendor_defined());
    }

    #[test]
    fn ck_result_ok() {
        let r: CkResult<u32> = Ok(42);
        assert!(r.is_ok());
    }

    #[test]
    fn ck_result_err() {
        let r: CkResult<u32> = Err(CkRv::MECHANISM_INVALID);
        assert_eq!(r, Err(CkRv::MECHANISM_INVALID));
    }
}
