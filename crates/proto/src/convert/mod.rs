pub mod attribute;
pub mod authenticated;
pub mod error;
pub mod mechanism;
pub mod mechanism_registry;
pub mod message_effects;
pub mod message_params;
pub mod output;
pub mod session;
pub mod slot;

use pkcs11_proxy_ng_types::CkRv;

/// W1-C8-03: the single `CK_RV` every absent-required-oneof wire decode in
/// the MessageParameter/Effects/Auth sibling group reports.
///
/// A missing oneof is a malformed peer message, not an unsupported function
/// (`MessageEffects` previously said `FUNCTION_NOT_SUPPORTED`) and not a
/// mechanism-shape violation (`AuthenticatedOutput` previously said
/// `MECHANISM_PARAM_INVALID`): `ARGUMENTS_BAD` is the PKCS#11 value for
/// malformed call arguments, and the server contract tests already pin it
/// for the `MessageParameter` sibling. Present-but-invalid values (e.g.
/// `AuthenticatedMechanismOutput::Unchanged(false)`) keep their distinct
/// rejections; only the *absent* oneof unifies here.
pub(crate) const ABSENT_MESSAGE_ONEOF_RV: CkRv = CkRv::ARGUMENTS_BAD;
