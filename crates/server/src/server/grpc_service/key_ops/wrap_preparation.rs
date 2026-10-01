//! Common admission for ordinary, authenticated, and exact wrapping adapters.
//! Preparation may read authorization metadata; it never invokes native wrap.
use pkcs11_proxy_ng_types::shape_descriptors::Operation;
use pkcs11_proxy_ng_types::{
    CkObjectHandle, CkResult, CkRv, CkSessionHandle, ValidatedMechanismParams,
};
use tonic::Status;

use super::super::HandlerContext;
use super::super::authorization::{extract_is_permitted, mechanism_permitted};
use super::super::mechanism_handles::remap_mechanism_handles;
use super::super::mechanism_input::{
    check_operator_exclusion, current_registry_snapshot, daemon_validation_abis,
    sanitize_mechanism_input, validate_mechanism_transport,
};
use super::super::service_utils::{parse_mechanism, resolve_session_and_two_objects};
use crate::server::context_manager::ClientContextId;

pub(in crate::server::grpc_service) struct PreparedWrap {
    pub session: CkSessionHandle,
    pub wrapping_key: CkObjectHandle,
    pub key: CkObjectHandle,
    pub mechanism: ValidatedMechanismParams,
}

pub(in crate::server::grpc_service) async fn prepare_wrap(
    ctx: &HandlerContext,
    context_id: &ClientContextId,
    virtual_session: u64,
    virtual_wrapping_key: u64,
    virtual_key: u64,
    mechanism: Option<pkcs11_proxy_ng_proto::Mechanism>,
) -> Result<CkResult<PreparedWrap>, Status> {
    // Preserve ordinary WrapKey precedence. Direct denied/unknown objects are
    // forwarded as zero by the resolver (ADR-0012); embedded denied nonzero
    // handles are rejected by the remapper rather than made optional zeros.
    let (session, wrapping_key, key) = match resolve_session_and_two_objects(
        ctx,
        context_id,
        virtual_session,
        virtual_wrapping_key,
        virtual_key,
    )
    .await
    {
        Ok(handles) => handles,
        Err(rv) => return Ok(Err(rv)),
    };
    // S2 §6: single registry snapshot feeds exclusion and transport
    // validation for this request.
    let registry = match current_registry_snapshot(ctx) {
        Ok(registry) => registry,
        Err(rv) => return Ok(Err(rv)),
    };
    let mechanism = match parse_mechanism(mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => return Ok(Err(rv)),
    };
    // S2 §6: operator exclusion precedes authorization.
    if let Err(rv) = check_operator_exclusion(&registry, mechanism.mechanism_type) {
        return Ok(Err(rv));
    }
    // W1-C1-13: the mechanism gate runs before remap on every init handler
    // so identical dual-defect requests yield the same RV regardless of op.
    if !mechanism_permitted(ctx, context_id, virtual_session, mechanism.mechanism_type).await {
        return Ok(Err(CkRv::MECHANISM_INVALID));
    }
    // S2 §6: transport validation (representable-shape gate) over the
    // single snapshot precedes handle translation.
    let (daemon_native_abi, daemon_width_abi) = daemon_validation_abis();
    let validated = match validate_mechanism_transport(
        &registry,
        &mechanism,
        Operation::WrapKey,
        daemon_native_abi,
        daemon_width_abi,
    ) {
        Ok(validated) => validated,
        Err(rv) => return Ok(Err(rv)),
    };
    let validated =
        match remap_mechanism_handles(ctx, context_id, virtual_session, session.0, validated).await
        {
            Ok(validated) => validated,
            Err(rv) => return Ok(Err(rv)),
        };
    if !extract_is_permitted(ctx, context_id, virtual_session, virtual_key).await? {
        return Ok(Err(CkRv::KEY_FUNCTION_NOT_PERMITTED));
    }
    // R20 (S2 §6): optional sanitizer between remap and backend call —
    // applied once here in the single wrap funnel (after the extract
    // gate, so extract-denied requests keep their existing RV), so all
    // four wrap callers (wrap, authenticated, byte-exact,
    // parameter-exact) receive a sanitized mechanism with no downstream
    // re-check.
    let validated = match sanitize_mechanism_input(ctx.sanitize_inputs, validated) {
        Ok(validated) => validated,
        Err(rv) => return Ok(Err(rv)),
    };
    Ok(Ok(PreparedWrap { session, wrapping_key, key, mechanism: validated }))
}
