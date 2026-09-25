use tonic::{Request, Response, Status};

mod decrypt_digest;
mod sign_encrypt;

use crate::server::grpc_service::HandlerContext;

pub(super) async fn digest_encrypt_update(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::DigestEncryptUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DigestEncryptUpdateResponse>, Status> {
    sign_encrypt::digest_encrypt_update(ctx, request).await
}

pub(super) async fn decrypt_digest_update(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::DecryptDigestUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DecryptDigestUpdateResponse>, Status> {
    decrypt_digest::decrypt_digest_update(ctx, request).await
}

pub(super) async fn sign_encrypt_update(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::SignEncryptUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SignEncryptUpdateResponse>, Status> {
    sign_encrypt::sign_encrypt_update(ctx, request).await
}

pub(super) async fn decrypt_verify_update(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::DecryptVerifyUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DecryptVerifyUpdateResponse>, Status> {
    decrypt_digest::decrypt_verify_update(ctx, request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend};
    use pkcs11_proxy_ng_types::{CkMechanismType, CkRv, CkSlotId};

    use crate::server::context_manager::ContextManager;

    fn test_handler() -> (Arc<ContextManager>, HandlerContext) {
        let mock = MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]);
        let backend: Arc<dyn Pkcs11Backend> = Arc::new(mock);
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(60), 0));
        let handler = HandlerContext::for_test(&ctx_mgr, &backend);
        (ctx_mgr, handler)
    }

    // W1-L11-06 characterization: every combined update handler must map
    // unknown-context / unknown-session to CRYPTOKI_NOT_INITIALIZED /
    // SESSION_HANDLE_INVALID. Must pass before AND after the resolver DRY.

    #[tokio::test]
    async fn t7_combined_handlers_reject_unknown_session() {
        let (ctx_mgr, handler) = test_handler();
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();

        let rv = digest_encrypt_update(
            &handler,
            Request::new(pkcs11_proxy_ng_proto::DigestEncryptUpdateRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: 9_999_999,
                part: vec![],
                part_null_len: None,
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .ck_rv;
        assert_eq!(rv, CkRv::SESSION_HANDLE_INVALID.0);

        let rv = decrypt_digest_update(
            &handler,
            Request::new(pkcs11_proxy_ng_proto::DecryptDigestUpdateRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: 9_999_999,
                encrypted_part: vec![],
                encrypted_part_null_len: None,
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .ck_rv;
        assert_eq!(rv, CkRv::SESSION_HANDLE_INVALID.0);

        let rv = sign_encrypt_update(
            &handler,
            Request::new(pkcs11_proxy_ng_proto::SignEncryptUpdateRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: 9_999_999,
                part: vec![],
                part_null_len: None,
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .ck_rv;
        assert_eq!(rv, CkRv::SESSION_HANDLE_INVALID.0);

        let rv = decrypt_verify_update(
            &handler,
            Request::new(pkcs11_proxy_ng_proto::DecryptVerifyUpdateRequest {
                client_context_id: ctx_id.0.clone(),
                session_handle: 9_999_999,
                encrypted_part: vec![],
                encrypted_part_null_len: None,
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .ck_rv;
        assert_eq!(rv, CkRv::SESSION_HANDLE_INVALID.0);
    }

    #[tokio::test]
    async fn t7_combined_handlers_reject_unknown_context() {
        let (_ctx_mgr, handler) = test_handler();

        let rv = digest_encrypt_update(
            &handler,
            Request::new(pkcs11_proxy_ng_proto::DigestEncryptUpdateRequest {
                client_context_id: "t7-gone".into(),
                session_handle: 1,
                part: vec![],
                part_null_len: None,
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .ck_rv;
        assert_eq!(rv, CkRv::CRYPTOKI_NOT_INITIALIZED.0);

        let rv = decrypt_digest_update(
            &handler,
            Request::new(pkcs11_proxy_ng_proto::DecryptDigestUpdateRequest {
                client_context_id: "t7-gone".into(),
                session_handle: 1,
                encrypted_part: vec![],
                encrypted_part_null_len: None,
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .ck_rv;
        assert_eq!(rv, CkRv::CRYPTOKI_NOT_INITIALIZED.0);

        let rv = sign_encrypt_update(
            &handler,
            Request::new(pkcs11_proxy_ng_proto::SignEncryptUpdateRequest {
                client_context_id: "t7-gone".into(),
                session_handle: 1,
                part: vec![],
                part_null_len: None,
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .ck_rv;
        assert_eq!(rv, CkRv::CRYPTOKI_NOT_INITIALIZED.0);

        let rv = decrypt_verify_update(
            &handler,
            Request::new(pkcs11_proxy_ng_proto::DecryptVerifyUpdateRequest {
                client_context_id: "t7-gone".into(),
                session_handle: 1,
                encrypted_part: vec![],
                encrypted_part_null_len: None,
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .ck_rv;
        assert_eq!(rv, CkRv::CRYPTOKI_NOT_INITIALIZED.0);
    }
}
