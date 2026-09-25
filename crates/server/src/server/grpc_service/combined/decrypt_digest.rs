// ADR-0013 §5: every `secret_to_plain` use in this file is a prost wire-encoding
// boundary (response/request construction); the standing justification lives in
// `secret_boundary` docs. No plain copy is retained past the enclosing encode.
use pkcs11_proxy_ng_proto::secret_boundary::secret_to_plain;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_types::*;

use super::super::super::context_manager::ClientContextId;
use super::super::HandlerContext;
use super::super::{
    ck_result_to_rv,
    service_utils::{resolve_session, spawn_backend},
};

// NOTE: legacy per-op RPC (W1-L11-21 retention; see service.proto) — not used by the shim; NULL-input class not forwarded (ADR-0010 Scope 2 covers the *_exact paths).
pub(super) async fn decrypt_digest_update(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::DecryptDigestUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DecryptDigestUpdateResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);
    let session = match resolve_session(&ctx.context_manager, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptDigestUpdateResponse {
                ck_rv: error.0,
                part: vec![],
            }));
        }
    };

    // W1-C1-17: hold caller input in `SecretBytes` (the sibling
    // `sign_encrypt.rs` convention), wiping on drop.
    let encrypted_part = SecretBytes::new(req.encrypted_part);
    let backend = ctx.backend.clone();
    let result = spawn_backend(move || {
        encrypted_part.expose(|raw| backend.decrypt_digest_update(session, CkInBuf::Bytes(raw)))
    })
    .await?;
    let (ck_rv, part) = ck_result_to_rv(result);
    Ok(Response::new(pkcs11_proxy_ng_proto::DecryptDigestUpdateResponse {
        ck_rv,
        part: secret_to_plain(&part.unwrap_or_default()),
    }))
}

// NOTE: legacy per-op RPC (W1-L11-21 retention; see service.proto) — not used by the shim; NULL-input class not forwarded (ADR-0010 Scope 2 covers the *_exact paths).
pub(super) async fn decrypt_verify_update(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::DecryptVerifyUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DecryptVerifyUpdateResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);
    let session = match resolve_session(&ctx.context_manager, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptVerifyUpdateResponse {
                ck_rv: error.0,
                part: vec![],
            }));
        }
    };

    // W1-C1-17: hold caller input in `SecretBytes` (the sibling
    // `sign_encrypt.rs` convention), wiping on drop.
    let encrypted_part = SecretBytes::new(req.encrypted_part);
    let backend = ctx.backend.clone();
    let result = spawn_backend(move || {
        encrypted_part.expose(|raw| backend.decrypt_verify_update(session, CkInBuf::Bytes(raw)))
    })
    .await?;
    let (ck_rv, part) = ck_result_to_rv(result);
    Ok(Response::new(pkcs11_proxy_ng_proto::DecryptVerifyUpdateResponse {
        ck_rv,
        part: secret_to_plain(&part.unwrap_or_default()),
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tonic::Request;

    use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend};
    use pkcs11_proxy_ng_types::*;

    use crate::server::context_manager::{ClientContextId, ContextManager};
    use crate::server::grpc_service::HandlerContext;
    use crate::server::handle_map::BackendHandle;

    /// W1-C1-17: both update fns must hold caller input in `SecretBytes`
    /// (the sibling `sign_encrypt.rs` convention), wiping on drop, instead
    /// of a plain `Vec` binding. Wiping is not API-observable, so this
    /// pins the holder construction at the call site (repo precedent:
    /// source-scan gates in `session/tests.rs`).
    #[test]
    fn c1_17_inputs_held_in_wiping_secret_bytes() {
        let src = include_str!("decrypt_digest.rs");
        // Patterns are built via concat so the assertions do not match
        // their own source text.
        let holder = ["SecretBytes", "new(req.encrypted_part)"].join("::");
        assert_eq!(
            src.matches(&holder).count(),
            2,
            "both update fns must wrap caller input in SecretBytes"
        );
        let plain = ["let encrypted_part", "req.encrypted_part;"].join(" = ");
        assert!(!src.contains(&plain), "caller input must not sit in a plain Vec binding");
    }

    async fn setup() -> (HandlerContext, ClientContextId, u64) {
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
        mock.initialize().unwrap();
        let backend_session = mock.open_session(CkSlotId(0), CkSessionFlags::default()).unwrap();
        let backend: Arc<dyn Pkcs11Backend> = mock;
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let session_vh = ctx_mgr
            .get_context(&ctx_id, |ctx| {
                ctx.register_session(
                    BackendHandle(backend_session.0),
                    crate::server::slot_map::BackendSlotId(CkSlotId(0)),
                )
            })
            .await
            .unwrap();
        let ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        (ctx, ctx_id, session_vh.0)
    }

    /// Functional pin: the SecretBytes holder must not change behavior —
    /// the mock xors the input bytes (0x42) and the handler forwards them.
    #[tokio::test]
    async fn c1_17_update_paths_forward_part_bytes_identically() {
        let (ctx, ctx_id, session) = setup().await;
        let input = vec![0x01, 0x02, 0x03, 0x04];
        let expected: Vec<u8> = input.iter().map(|b| b ^ 0x42).collect();

        let digest = super::decrypt_digest_update(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::DecryptDigestUpdateRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session,
                encrypted_part: input.clone(),
                encrypted_part_null_len: None,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(digest.ck_rv, CkRv::OK.0);
        assert_eq!(digest.part, expected);

        let verify = super::decrypt_verify_update(
            &ctx,
            Request::new(pkcs11_proxy_ng_proto::DecryptVerifyUpdateRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: session,
                encrypted_part: input,
                encrypted_part_null_len: None,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(verify.ck_rv, CkRv::OK.0);
        assert_eq!(verify.part, expected);
    }
}
