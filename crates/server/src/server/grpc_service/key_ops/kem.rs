//! gRPC handlers for PKCS#11 3.2 KEM operations (Wave 2).
//!
//! - `C_EncapsulateKey`
//! - `C_DecapsulateKey`

// ADR-0013 §5: every `secret_to_plain` use in this file is a prost wire-encoding
// boundary (response/request construction); the standing justification lives in
// `secret_boundary` docs. No plain copy is retained past the enclosing encode.
use pkcs11_proxy_ng_proto::secret_boundary::secret_to_plain;
use pkcs11_proxy_ng_proto::version::{
    exact_effects_version_rejected, exact_output_effects_version_supported,
};
use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_types::shape_descriptors::Operation;
use pkcs11_proxy_ng_types::{CkObjectHandle, CkOutputBufferSpec, CkRv};

use super::super::authorization::mechanism_permitted;
use super::super::convert_template_opt;
use super::super::mechanism_handles::remap_mechanism_handles;
use super::super::mechanism_input::{
    check_operator_exclusion, current_registry_snapshot, daemon_validation_abis,
    sanitize_mechanism_input, validate_mechanism_transport,
};
use super::super::service_utils::{
    ExactCompletion, LateMintedObjects, ObjectMintCompletionOwner, check_sanitize,
    ensure_private_mint_allowed, input_from_wire, parse_mechanism, register_session_object_handle,
    resolve_session_and_key, spawn_backend, spawn_backend_exact, template_declares_private_object,
    template_declares_token_object,
};
use crate::server::context_manager::ClientContextId;
use crate::server::handle_map::VirtualHandle;

use crate::server::grpc_service::HandlerContext;
// NOTE: legacy per-op RPC (W1-L11-21 retention; see service.proto) — not used by the shim; NULL-input class not forwarded (ADR-0010 Scope 2 covers the *_exact paths).
pub(crate) async fn encapsulate_key(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::EncapsulateKeyRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::EncapsulateKeyResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, public_key) = match resolve_session_and_key(
        ctx,
        &ctx_id,
        req.session_handle,
        req.public_key_handle,
    )
    .await
    {
        Ok(handles) => handles,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyResponse {
                ck_rv: rv.0,
                ciphertext: Vec::new(),
                key_handle: 0,
            }));
        }
    };

    // S2 §6: single registry snapshot feeds exclusion and transport
    // validation for this request.
    let registry = match current_registry_snapshot(ctx) {
        Ok(registry) => registry,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyResponse {
                ck_rv: rv.0,
                ciphertext: Vec::new(),
                key_handle: 0,
            }));
        }
    };
    let mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyResponse {
                ck_rv: rv.0,
                ciphertext: Vec::new(),
                key_handle: 0,
            }));
        }
    };
    // S2 §6: operator exclusion precedes authorization.
    if let Err(rv) = check_operator_exclusion(&registry, mechanism.mechanism_type) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyResponse {
            ck_rv: rv.0,
            ciphertext: Vec::new(),
            key_handle: 0,
        }));
    }

    if !mechanism_permitted(ctx, &ctx_id, req.session_handle, mechanism.mechanism_type).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyResponse {
            ck_rv: CkRv::MECHANISM_INVALID.0,
            ciphertext: Vec::new(),
            key_handle: 0,
        }));
    }

    // S2 §6: transport validation (representable-shape gate) over the
    // single snapshot precedes handle translation.
    let (daemon_native_abi, daemon_width_abi) = daemon_validation_abis();
    let validated = match validate_mechanism_transport(
        &registry,
        &mechanism,
        Operation::General,
        daemon_native_abi,
        daemon_width_abi,
    ) {
        Ok(validated) => validated,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyResponse {
                ck_rv: rv.0,
                ciphertext: Vec::new(),
                key_handle: 0,
            }));
        }
    };
    // B1: remap object handles embedded in the mechanism parameters;
    // gate each through per-object authz when active (C1).
    let validated =
        match remap_mechanism_handles(ctx, &ctx_id, req.session_handle, session.0, validated).await
        {
            Ok(validated) => validated,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyResponse {
                    ck_rv: rv.0,
                    ciphertext: Vec::new(),
                    key_handle: 0,
                }));
            }
        };

    let template = match convert_template_opt(&req.template, req.template_null) {
        Ok(template) => template,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyResponse {
                ck_rv: rv,
                ciphertext: Vec::new(),
                key_handle: 0,
            }));
        }
    };

    // A NULL template carries no attributes; classification treats it as empty.
    let template_view = template.as_deref().unwrap_or(&[]);

    // D6(1): refuse minting a private object while logically logged out.
    if let Err(rv) =
        ensure_private_mint_allowed(ctx_mgr, &ctx_id, req.session_handle, template_view).await
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyResponse {
            ck_rv: rv.0,
            ciphertext: Vec::new(),
            key_handle: 0,
        }));
    }

    // An encapsulated key is a session object unless CKA_TOKEN is set (B2).
    // The privacy bit is recorded for the D6(1) USE enforcement.
    let is_token = template_declares_token_object(template_view);
    let is_private = template_declares_private_object(template_view);
    let virtual_session = VirtualHandle(req.session_handle);
    let backend = Arc::clone(backend_ref);
    // R20 (S2 §6): optional sanitizer between remap and backend call.
    let validated = match sanitize_mechanism_input(ctx.sanitize_inputs, validated) {
        Ok(validated) => validated,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyResponse {
                ck_rv: rv.0,
                ciphertext: Vec::new(),
                key_handle: 0,
            }));
        }
    };
    // P2-13: own the late result until registration adopts the key.
    // Only the handle integer is reported to the owner — never the
    // ciphertext.
    let (completion_tx, mut completion_owner) = ObjectMintCompletionOwner::arm(backend_ref);
    let result = spawn_backend(move || {
        let outcome = backend.encapsulate_key(session, &validated, public_key, template.as_deref());
        let _ = completion_tx.send(match &outcome {
            Ok((_, key)) => Ok(LateMintedObjects::single(session, CkObjectHandle(key.0 as u64))),
            Err(rv) => Err(*rv),
        });
        outcome
    })
    .await?;

    match result {
        Ok((ciphertext, key)) => {
            let key_handle = register_session_object_handle(
                ctx_mgr,
                &ctx_id,
                virtual_session,
                CkObjectHandle(key.0 as u64),
                is_token,
                Some(is_private),
            )
            .await;
            if key_handle != 0 {
                completion_owner.disarm();
            }
            Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyResponse {
                ck_rv: CkRv::OK.0,
                ciphertext: secret_to_plain(&ciphertext),
                key_handle,
            }))
        }
        Err(error) => {
            completion_owner.settle_on_error();
            Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyResponse {
                ck_rv: error.0,
                ciphertext: Vec::new(),
                key_handle: 0,
            }))
        }
    }
}

pub(crate) async fn decapsulate_key(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::DecapsulateKeyRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DecapsulateKeyResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, private_key) =
        match resolve_session_and_key(ctx, &ctx_id, req.session_handle, req.private_key_handle)
            .await
        {
            Ok(handles) => handles,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::DecapsulateKeyResponse {
                    ck_rv: rv.0,
                    key_handle: 0,
                }));
            }
        };

    // S2 §6: single registry snapshot feeds exclusion and transport
    // validation for this request.
    let registry = match current_registry_snapshot(ctx) {
        Ok(registry) => registry,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DecapsulateKeyResponse {
                ck_rv: rv.0,
                key_handle: 0,
            }));
        }
    };
    let mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DecapsulateKeyResponse {
                ck_rv: rv.0,
                key_handle: 0,
            }));
        }
    };
    // S2 §6: operator exclusion precedes authorization.
    if let Err(rv) = check_operator_exclusion(&registry, mechanism.mechanism_type) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::DecapsulateKeyResponse {
            ck_rv: rv.0,
            key_handle: 0,
        }));
    }

    if !mechanism_permitted(ctx, &ctx_id, req.session_handle, mechanism.mechanism_type).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::DecapsulateKeyResponse {
            ck_rv: CkRv::MECHANISM_INVALID.0,
            key_handle: 0,
        }));
    }

    // S2 §6: transport validation (representable-shape gate) over the
    // single snapshot precedes handle translation.
    let (daemon_native_abi, daemon_width_abi) = daemon_validation_abis();
    let validated = match validate_mechanism_transport(
        &registry,
        &mechanism,
        Operation::General,
        daemon_native_abi,
        daemon_width_abi,
    ) {
        Ok(validated) => validated,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DecapsulateKeyResponse {
                ck_rv: rv.0,
                key_handle: 0,
            }));
        }
    };
    // B1: remap object handles embedded in the mechanism parameters;
    // gate each through per-object authz when active (C1).
    let validated =
        match remap_mechanism_handles(ctx, &ctx_id, req.session_handle, session.0, validated).await
        {
            Ok(validated) => validated,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::DecapsulateKeyResponse {
                    ck_rv: rv.0,
                    key_handle: 0,
                }));
            }
        };

    let template = match convert_template_opt(&req.template, req.template_null) {
        Ok(template) => template,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DecapsulateKeyResponse {
                ck_rv: rv,
                key_handle: 0,
            }));
        }
    };

    // A NULL template carries no attributes; classification treats it as empty.
    let template_view = template.as_deref().unwrap_or(&[]);

    // D6(1): refuse minting a private object while logically logged out.
    // (The private KEM key itself is refused by the USE check inside
    // resolve_session_and_key above.)
    if let Err(rv) =
        ensure_private_mint_allowed(ctx_mgr, &ctx_id, req.session_handle, template_view).await
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::DecapsulateKeyResponse {
            ck_rv: rv.0,
            key_handle: 0,
        }));
    }

    // A decapsulated key is a session object unless CKA_TOKEN is set (B2).
    // The privacy bit is recorded for the D6(1) USE enforcement.
    let is_token = template_declares_token_object(template_view);
    let is_private = template_declares_private_object(template_view);
    let virtual_session = VirtualHandle(req.session_handle);
    let ciphertext = req.ciphertext;
    let ciphertext_null_len = req.ciphertext_null_len;
    // ADR-0010 sanitize_inputs: validate NULL ciphertext pointer before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, ciphertext_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::DecapsulateKeyResponse {
            ck_rv: rv.0,
            key_handle: 0,
        }));
    }
    let backend = Arc::clone(backend_ref);
    // R20 (S2 §6): optional sanitizer between remap and backend call.
    let validated = match sanitize_mechanism_input(ctx.sanitize_inputs, validated) {
        Ok(validated) => validated,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DecapsulateKeyResponse {
                ck_rv: rv.0,
                key_handle: 0,
            }));
        }
    };
    // P2-13: own the late result until registration adopts the key.
    let (completion_tx, mut completion_owner) = ObjectMintCompletionOwner::arm(backend_ref);
    let result = spawn_backend(move || {
        let outcome = backend.decapsulate_key(
            session,
            &validated,
            private_key,
            template.as_deref(),
            input_from_wire(&ciphertext, ciphertext_null_len),
        );
        let _ = completion_tx.send(match &outcome {
            Ok(key) => Ok(LateMintedObjects::single(session, CkObjectHandle(key.0 as u64))),
            Err(rv) => Err(*rv),
        });
        outcome
    })
    .await?;

    match result {
        Ok(key) => {
            let key_handle = register_session_object_handle(
                ctx_mgr,
                &ctx_id,
                virtual_session,
                CkObjectHandle(key.0 as u64),
                is_token,
                Some(is_private),
            )
            .await;
            if key_handle != 0 {
                completion_owner.disarm();
            }
            Ok(Response::new(pkcs11_proxy_ng_proto::DecapsulateKeyResponse {
                ck_rv: CkRv::OK.0,
                key_handle,
            }))
        }
        Err(error) => {
            completion_owner.settle_on_error();
            Ok(Response::new(pkcs11_proxy_ng_proto::DecapsulateKeyResponse {
                ck_rv: error.0,
                key_handle: 0,
            }))
        }
    }
}

pub(crate) async fn encapsulate_key_exact(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::EncapsulateKeyExactRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::EncapsulateKeyExactResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let req = request.into_inner();
    // W1-L5-04: compatibility-range gate, never an equality literal.
    if !exact_output_effects_version_supported(req.exact_output_effects_version) {
        return Err(exact_effects_version_rejected(req.exact_output_effects_version));
    }
    let ctx_id = ClientContextId(req.client_context_id);

    let (session, public_key) = match resolve_session_and_key(
        ctx,
        &ctx_id,
        req.session_handle,
        req.public_key_handle,
    )
    .await
    {
        Ok(handles) => handles,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyExactResponse {
                result: Some(pkcs11_proxy_ng_proto::OutputAndHandleResult {
                    apply_returned_len: Some(false),
                    apply_object_handle: Some(false),
                    ck_rv: rv.0,
                    returned_len: 0,
                    value: None,
                    object_handle: 0,
                }),
            }));
        }
    };

    // S2 §6: single registry snapshot feeds exclusion and transport
    // validation for this request.
    let registry = match current_registry_snapshot(ctx) {
        Ok(registry) => registry,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyExactResponse {
                result: Some(pkcs11_proxy_ng_proto::OutputAndHandleResult {
                    apply_returned_len: Some(false),
                    apply_object_handle: Some(false),
                    ck_rv: rv.0,
                    returned_len: 0,
                    value: None,
                    object_handle: 0,
                }),
            }));
        }
    };
    let mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyExactResponse {
                result: Some(pkcs11_proxy_ng_proto::OutputAndHandleResult {
                    apply_returned_len: Some(false),
                    apply_object_handle: Some(false),
                    ck_rv: rv.0,
                    returned_len: 0,
                    value: None,
                    object_handle: 0,
                }),
            }));
        }
    };
    // S2 §6: operator exclusion precedes authorization.
    if let Err(rv) = check_operator_exclusion(&registry, mechanism.mechanism_type) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyExactResponse {
            result: Some(pkcs11_proxy_ng_proto::OutputAndHandleResult {
                apply_returned_len: Some(false),
                apply_object_handle: Some(false),
                ck_rv: rv.0,
                returned_len: 0,
                value: None,
                object_handle: 0,
            }),
        }));
    }

    if !mechanism_permitted(ctx, &ctx_id, req.session_handle, mechanism.mechanism_type).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyExactResponse {
            result: Some(pkcs11_proxy_ng_proto::OutputAndHandleResult {
                apply_returned_len: Some(false),
                apply_object_handle: Some(false),
                ck_rv: CkRv::MECHANISM_INVALID.0,
                returned_len: 0,
                value: None,
                object_handle: 0,
            }),
        }));
    }

    // S2 §6: transport validation (representable-shape gate) over the
    // single snapshot precedes handle translation.
    let (daemon_native_abi, daemon_width_abi) = daemon_validation_abis();
    let validated = match validate_mechanism_transport(
        &registry,
        &mechanism,
        Operation::General,
        daemon_native_abi,
        daemon_width_abi,
    ) {
        Ok(validated) => validated,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyExactResponse {
                result: Some(pkcs11_proxy_ng_proto::OutputAndHandleResult {
                    apply_returned_len: Some(false),
                    apply_object_handle: Some(false),
                    ck_rv: rv.0,
                    returned_len: 0,
                    value: None,
                    object_handle: 0,
                }),
            }));
        }
    };
    // B1: remap object handles embedded in the mechanism parameters;
    // gate each through per-object authz when active (C1).
    let validated =
        match remap_mechanism_handles(ctx, &ctx_id, req.session_handle, session.0, validated).await
        {
            Ok(validated) => validated,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyExactResponse {
                    result: Some(pkcs11_proxy_ng_proto::OutputAndHandleResult {
                        apply_returned_len: Some(false),
                        apply_object_handle: Some(false),
                        ck_rv: rv.0,
                        returned_len: 0,
                        value: None,
                        object_handle: 0,
                    }),
                }));
            }
        };

    let template = match convert_template_opt(&req.template, req.template_null) {
        Ok(template) => template,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyExactResponse {
                result: Some(pkcs11_proxy_ng_proto::OutputAndHandleResult {
                    apply_returned_len: Some(false),
                    apply_object_handle: Some(false),
                    ck_rv: rv,
                    returned_len: 0,
                    value: None,
                    object_handle: 0,
                }),
            }));
        }
    };

    // A NULL template carries no attributes; classification treats it as empty.
    let template_view = template.as_deref().unwrap_or(&[]);

    // D6(1): refuse minting a private object while logically logged out.
    if let Err(rv) =
        ensure_private_mint_allowed(ctx_mgr, &ctx_id, req.session_handle, template_view).await
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyExactResponse {
            result: Some(pkcs11_proxy_ng_proto::OutputAndHandleResult {
                apply_returned_len: Some(false),
                apply_object_handle: Some(false),
                ck_rv: rv.0,
                returned_len: 0,
                value: None,
                object_handle: 0,
            }),
        }));
    }

    let spec =
        req.output_spec.as_ref().map(CkOutputBufferSpec::from).unwrap_or(CkOutputBufferSpec {
            buffer_present: false,
            buffer_len: 0,
            length_pointer_null: false,
        });

    // The exact-encapsulated key is a session object unless CKA_TOKEN is set (B2).
    // The privacy bit is recorded for the D6(1) USE enforcement.
    let is_token = template_declares_token_object(template_view);
    let is_private = template_declares_private_object(template_view);
    let virtual_session = VirtualHandle(req.session_handle);
    let backend = Arc::clone(backend_ref);
    // R20 (S2 §6): optional sanitizer between remap and backend call.
    // (T2 shape: errors carry apply_* = Some(false), mirroring the
    // adjacent arms.)
    let validated = match sanitize_mechanism_input(ctx.sanitize_inputs, validated) {
        Ok(validated) => validated,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyExactResponse {
                result: Some(pkcs11_proxy_ng_proto::OutputAndHandleResult {
                    apply_returned_len: Some(false),
                    apply_object_handle: Some(false),
                    ck_rv: rv.0,
                    returned_len: 0,
                    value: None,
                    object_handle: 0,
                }),
            }));
        }
    };
    // P2-13: own the late result until registration adopts the key.
    // The extraction trusts `object_handle` under the identical
    // condition registration uses below (`CKR_OK` + non-zero); the
    // exact health classification is untouched (`ExactCompletion`
    // still captures the raw outcome).
    let (completion_tx, mut completion_owner) = ObjectMintCompletionOwner::arm(backend_ref);
    let result = spawn_backend_exact(move || {
        let outcome = backend.encapsulate_key_exact(
            session,
            &validated,
            public_key,
            template.as_deref(),
            &spec,
        );
        let _ = completion_tx.send(match &outcome {
            Ok(r) if r.ck_rv == CkRv::OK => Ok(LateMintedObjects::new(session, r.object_handle)),
            Ok(r) => Err(r.ck_rv),
            Err(rv) => Err(*rv),
        });
        ExactCompletion::capture(outcome)
    })
    .await?;

    match result {
        Ok(r) => {
            // Register the returned object handle through the context manager
            let minted = r.ck_rv == CkRv::OK && r.object_handle.is_some_and(|h| h.0 != 0);
            let virtual_handle = if r.ck_rv == CkRv::OK
                && let Some(handle) = r.object_handle.filter(|h| h.0 != 0)
            {
                register_session_object_handle(
                    ctx_mgr,
                    &ctx_id,
                    virtual_session,
                    handle,
                    is_token,
                    Some(is_private),
                )
                .await
            } else {
                0
            };
            // Adopted (or nothing minted): disarm. A minted key whose
            // registration failed stays armed for settlement destroy.
            if !minted || virtual_handle != 0 {
                completion_owner.disarm();
            }
            Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyExactResponse {
                result: Some(pkcs11_proxy_ng_proto::OutputAndHandleResult {
                    apply_returned_len: Some(r.returned_len.is_some()),
                    apply_object_handle: Some(virtual_handle != 0),
                    ck_rv: r.ck_rv.0,
                    returned_len: r.returned_len.unwrap_or(0),
                    value: r
                        .value
                        .as_ref()
                        .map(pkcs11_proxy_ng_proto::secret_boundary::secret_to_plain),
                    object_handle: virtual_handle,
                }),
            }))
        }
        Err(error) => {
            completion_owner.settle_on_error();
            Ok(Response::new(pkcs11_proxy_ng_proto::EncapsulateKeyExactResponse {
                result: Some(pkcs11_proxy_ng_proto::OutputAndHandleResult {
                    apply_returned_len: Some(false),
                    apply_object_handle: Some(false),
                    ck_rv: error.0,
                    returned_len: 0,
                    value: None,
                    object_handle: 0,
                }),
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend};
    use pkcs11_proxy_ng_types::{CkMechanismType, CkSessionFlags, CkSlotId};

    use crate::server::context_manager::ContextManager;
    use crate::server::grpc_service::service_utils::{
        register_session_handle, register_session_object_handle,
    };

    #[tokio::test]
    async fn missing_output_length_is_forwarded_to_kem_backend() {
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
        mock.initialize().unwrap();
        let backend_session =
            mock.open_session(CkSlotId(0), CkSessionFlags::SERIAL_SESSION).unwrap();
        let public_key = mock.create_object(backend_session, Some(&[])).unwrap();
        let backend: Arc<dyn Pkcs11Backend> = mock;
        let manager = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        manager.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let context_id = manager.create_context(None).await.unwrap();
        let virtual_session = register_session_handle(
            &manager,
            &context_id,
            backend_session,
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
        )
        .await
        .unwrap();
        let virtual_session = VirtualHandle(virtual_session);
        let virtual_public_key = register_session_object_handle(
            &manager,
            &context_id,
            virtual_session,
            public_key,
            false,
            None,
        )
        .await;

        let result = encapsulate_key_exact(
            &HandlerContext::for_test(&manager, &backend),
            Request::new(pkcs11_proxy_ng_proto::EncapsulateKeyExactRequest {
                exact_output_effects_version: 1,
                client_context_id: context_id.0,
                session_handle: virtual_session.0,
                mechanism: Some(pkcs11_proxy_ng_proto::Mechanism {
                    mechanism_type: CkMechanismType::RSA_PKCS.0,
                    params: None,
                    parameter_encoding_version: 0,
                }),
                public_key_handle: virtual_public_key,
                template: Vec::new(),
                output_spec: Some(pkcs11_proxy_ng_proto::OutputBufferSpec {
                    buffer_present: true,
                    buffer_len: 0,
                    length_pointer_null: true,
                }),

                template_null: false,
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .result
        .unwrap();

        assert_eq!(result.ck_rv, CkRv::ARGUMENTS_BAD.0);
        assert_eq!(result.returned_len, 0);
        assert_eq!(result.value, None);
        assert_eq!(result.object_handle, 0);
    }

    /// P2-13 fixture: mock + session + one key object. Returns
    /// (mock, backend, manager, context_id, virtual session,
    /// virtual key).
    async fn kem_settlement_fixture() -> (
        Arc<MockBackend>,
        Arc<dyn Pkcs11Backend>,
        Arc<ContextManager>,
        crate::server::context_manager::ClientContextId,
        u64,
        u64,
    ) {
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
        mock.initialize().unwrap();
        let backend_session =
            mock.open_session(CkSlotId(0), CkSessionFlags::SERIAL_SESSION).unwrap();
        let key = mock.create_object(backend_session, Some(&[])).unwrap();
        let backend: Arc<dyn Pkcs11Backend> = mock.clone();
        let manager = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        manager.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let context_id = manager.create_context(None).await.unwrap();
        let virtual_session = register_session_handle(
            &manager,
            &context_id,
            backend_session,
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
        )
        .await
        .unwrap();
        let virtual_key = register_session_object_handle(
            &manager,
            &context_id,
            VirtualHandle(virtual_session),
            key,
            false,
            Some(false),
        )
        .await;
        (mock, backend, manager, context_id, virtual_session, virtual_key)
    }

    fn rsa_pkcs_proto() -> pkcs11_proxy_ng_proto::Mechanism {
        pkcs11_proxy_ng_proto::Mechanism {
            mechanism_type: CkMechanismType::RSA_PKCS.0,
            params: None,
            parameter_encoding_version: 0,
        }
    }

    async fn await_kem_settlement(mock: &Arc<MockBackend>, live: usize, destroys: usize) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if mock.live_object_count() == live && mock.destroy_call_count() == destroys {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for mint settlement: live={} destroys={} (want live={live} destroys={destroys})",
                mock.live_object_count(),
                mock.destroy_call_count()
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// P2-13: cancelling EncapsulateKey after native entry destroys
    /// the late encapsulated key exactly once.
    #[tokio::test]
    async fn encapsulate_key_cancel_after_entry_leaves_no_orphan() {
        let (mock, backend, manager, context_id, session, key) = kem_settlement_fixture().await;
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        mock.set_mint_gate(entered_tx, release_rx);

        let rpc = {
            let (manager, backend, context_id) =
                (manager.clone(), backend.clone(), context_id.clone());
            tokio::spawn(async move {
                encapsulate_key(
                    &HandlerContext::for_test(&manager, &backend),
                    Request::new(pkcs11_proxy_ng_proto::EncapsulateKeyRequest {
                        client_context_id: context_id.0.clone(),
                        session_handle: session,
                        mechanism: Some(rsa_pkcs_proto()),
                        public_key_handle: key,
                        template: vec![],
                        template_null: false,
                    }),
                )
                .await
            })
        };
        let op = tokio::task::spawn_blocking(move || {
            entered_rx.recv_timeout(Duration::from_secs(10)).expect("native entry observed")
        })
        .await
        .unwrap();
        assert_eq!(op, "encapsulate_key");
        rpc.abort();
        assert!(rpc.await.expect_err("aborted join must err").is_cancelled());
        release_tx.send(()).expect("parked worker alive");
        await_kem_settlement(&mock, 1, 1).await;
    }

    /// P2-13: cancelling DecapsulateKey after native entry destroys
    /// the late decapsulated key exactly once.
    #[tokio::test]
    async fn decapsulate_key_cancel_after_entry_leaves_no_orphan() {
        let (mock, backend, manager, context_id, session, key) = kem_settlement_fixture().await;
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        mock.set_mint_gate(entered_tx, release_rx);

        let rpc = {
            let (manager, backend, context_id) =
                (manager.clone(), backend.clone(), context_id.clone());
            tokio::spawn(async move {
                decapsulate_key(
                    &HandlerContext::for_test(&manager, &backend),
                    Request::new(pkcs11_proxy_ng_proto::DecapsulateKeyRequest {
                        client_context_id: context_id.0.clone(),
                        session_handle: session,
                        mechanism: Some(rsa_pkcs_proto()),
                        private_key_handle: key,
                        template: vec![],
                        template_null: false,
                        ciphertext: vec![9; 16],
                        ciphertext_null_len: None,
                    }),
                )
                .await
            })
        };
        let op = tokio::task::spawn_blocking(move || {
            entered_rx.recv_timeout(Duration::from_secs(10)).expect("native entry observed")
        })
        .await
        .unwrap();
        assert_eq!(op, "decapsulate_key");
        rpc.abort();
        assert!(rpc.await.expect_err("aborted join must err").is_cancelled());
        release_tx.send(()).expect("parked worker alive");
        await_kem_settlement(&mock, 1, 1).await;
    }

    /// P2-13: cancelling EncapsulateKeyExact after native entry
    /// destroys the late exact-encapsulated key exactly once.
    #[tokio::test]
    async fn encapsulate_key_exact_cancel_after_entry_leaves_no_orphan() {
        let (mock, backend, manager, context_id, session, key) = kem_settlement_fixture().await;
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        mock.set_mint_gate(entered_tx, release_rx);

        let rpc = {
            let (manager, backend, context_id) =
                (manager.clone(), backend.clone(), context_id.clone());
            tokio::spawn(async move {
                encapsulate_key_exact(
                    &HandlerContext::for_test(&manager, &backend),
                    Request::new(pkcs11_proxy_ng_proto::EncapsulateKeyExactRequest {
                        exact_output_effects_version: 1,
                        client_context_id: context_id.0.clone(),
                        session_handle: session,
                        mechanism: Some(rsa_pkcs_proto()),
                        public_key_handle: key,
                        template: Vec::new(),
                        output_spec: Some(pkcs11_proxy_ng_proto::OutputBufferSpec {
                            buffer_present: true,
                            buffer_len: 1024,
                            length_pointer_null: false,
                        }),
                        template_null: false,
                    }),
                )
                .await
            })
        };
        let op = tokio::task::spawn_blocking(move || {
            entered_rx.recv_timeout(Duration::from_secs(10)).expect("native entry observed")
        })
        .await
        .unwrap();
        assert_eq!(op, "encapsulate_key_exact");
        rpc.abort();
        assert!(rpc.await.expect_err("aborted join must err").is_cancelled());
        release_tx.send(()).expect("parked worker alive");
        await_kem_settlement(&mock, 1, 1).await;
    }
}
