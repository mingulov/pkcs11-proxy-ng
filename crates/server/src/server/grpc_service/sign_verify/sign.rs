// ADR-0013 §5: every `secret_to_plain` use in this file is a prost wire-encoding
// boundary (response/request construction); the standing justification lives in
// `secret_boundary` docs. No plain copy is retained past the enclosing encode.
use pkcs11_proxy_ng_proto::secret_boundary::secret_to_plain;
use std::sync::Arc;
use std::time::Instant;

use pkcs11_proxy_ng_audit::EventClass;
use tonic::{Request, Response, Status};

use super::super::authorization::mechanism_permitted;
use super::super::ck_result_to_rv;
use super::super::mechanism_handles::remap_mechanism_handles;
use super::super::service_utils::{
    check_sanitize, ck_rv_only, input_from_wire, parse_mechanism, resolve_session,
    resolve_session_and_key, spawn_backend,
};
use crate::server::context_manager::ClientContextId;
use crate::server::grpc_service::audit_events::emit_auth_event;

use crate::server::grpc_service::HandlerContext;
pub(crate) async fn sign_init(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::SignInitRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SignInitResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    // ADR-0010 sanitize_inputs: reject NULL mechanism before reaching the module.
    if sanitize_inputs && req.mechanism.is_none() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::SignInitResponse {
            ck_rv: pkcs11_proxy_ng_types::CkRv::ARGUMENTS_BAD.0,
        }));
    }

    if req.mechanism.is_none() {
        let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
            Ok(session) => session,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::SignInitResponse { ck_rv: rv.0 }));
            }
        };
        let backend = Arc::clone(backend_ref);
        let result = spawn_backend(move || backend.sign_init_cancel(session)).await?;
        return Ok(Response::new(pkcs11_proxy_ng_proto::SignInitResponse {
            ck_rv: ck_rv_only(result),
        }));
    }

    let (session, key) =
        match resolve_session_and_key(ctx, &ctx_id, req.session_handle, req.key_handle).await {
            Ok(handles) => handles,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::SignInitResponse { ck_rv: rv.0 }));
            }
        };

    let mut mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SignInitResponse { ck_rv: rv.0 }));
        }
    };

    // B1: remap object handles embedded in the mechanism parameters;
    // gate each through per-object authz when active (C1).
    if let Err(rv) =
        remap_mechanism_handles(ctx, &ctx_id, req.session_handle, session.0, &mut mechanism).await
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::SignInitResponse { ck_rv: rv.0 }));
    }

    // Mechanism policy gate (G3-PR3 Task 3).
    if !mechanism_permitted(ctx, &ctx_id, req.session_handle, mechanism.mechanism_type).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::SignInitResponse {
            ck_rv: pkcs11_proxy_ng_types::CkRv::MECHANISM_INVALID.0,
        }));
    }

    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.sign_init(session, &mechanism, key)).await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::SignInitResponse { ck_rv: ck_rv_only(result) }))
}

pub(crate) async fn sign(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::SignRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SignResponse>, Status> {
    let started = Instant::now();
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SignResponse {
                ck_rv: rv.0,
                signature: Vec::new(),
            }));
        }
    };

    let data = req.data;
    let data_null_len = req.data_null_len;
    // ADR-0010 sanitize_inputs: validate NULL data pointer before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, data_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::SignResponse {
            ck_rv: rv.0,
            signature: Vec::new(),
        }));
    }
    let backend = Arc::clone(backend_ref);
    let result =
        spawn_backend(move || backend.sign(session, input_from_wire(&data, data_null_len))).await?;
    let (ck_rv, signature) = ck_result_to_rv(result);
    // Opt-in data-plane audit: emit fail-open; never reject the op on a dropped record.
    if ctx.audit.as_ref().is_some_and(|a| a.data_plane_enabled()) {
        let _ = emit_auth_event(
            ctx,
            &ctx_id,
            "C_Sign",
            EventClass::DataPlane,
            None,
            Some(req.session_handle),
            ck_rv,
            started,
        );
    }
    Ok(Response::new(pkcs11_proxy_ng_proto::SignResponse {
        ck_rv,
        signature: secret_to_plain(&signature.unwrap_or_default()),
    }))
}

pub(crate) async fn sign_update(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::SignUpdateRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SignUpdateResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SignUpdateResponse { ck_rv: rv.0 }));
        }
    };

    let part = req.part;
    let part_null_len = req.part_null_len;
    // ADR-0010 sanitize_inputs: validate NULL data pointer before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, part_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::SignUpdateResponse { ck_rv: rv.0 }));
    }
    let backend = Arc::clone(backend_ref);
    let result =
        spawn_backend(move || backend.sign_update(session, input_from_wire(&part, part_null_len)))
            .await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::SignUpdateResponse { ck_rv: ck_rv_only(result) }))
}

pub(crate) async fn sign_final(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::SignFinalRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SignFinalResponse>, Status> {
    let started = Instant::now();
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SignFinalResponse {
                ck_rv: rv.0,
                signature: Vec::new(),
            }));
        }
    };

    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.sign_final(session)).await?;
    let (ck_rv, signature) = ck_result_to_rv(result);
    // Opt-in data-plane audit: emit fail-open; never reject the op on a dropped record.
    if ctx.audit.as_ref().is_some_and(|a| a.data_plane_enabled()) {
        let _ = emit_auth_event(
            ctx,
            &ctx_id,
            "C_Sign",
            EventClass::DataPlane,
            None,
            Some(req.session_handle),
            ck_rv,
            started,
        );
    }
    Ok(Response::new(pkcs11_proxy_ng_proto::SignFinalResponse {
        ck_rv,
        signature: secret_to_plain(&signature.unwrap_or_default()),
    }))
}

pub(crate) async fn sign_recover_init(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::SignRecoverInitRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SignRecoverInitResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    // ADR-0010 sanitize_inputs: reject NULL mechanism before reaching the module.
    if sanitize_inputs && req.mechanism.is_none() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::SignRecoverInitResponse {
            ck_rv: pkcs11_proxy_ng_types::CkRv::ARGUMENTS_BAD.0,
        }));
    }

    if req.mechanism.is_none() {
        let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
            Ok(session) => session,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::SignRecoverInitResponse {
                    ck_rv: rv.0,
                }));
            }
        };
        let backend = Arc::clone(backend_ref);
        let result = spawn_backend(move || backend.sign_recover_init_cancel(session)).await?;
        return Ok(Response::new(pkcs11_proxy_ng_proto::SignRecoverInitResponse {
            ck_rv: ck_rv_only(result),
        }));
    }

    let (session, key) =
        match resolve_session_and_key(ctx, &ctx_id, req.session_handle, req.key_handle).await {
            Ok(handles) => handles,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::SignRecoverInitResponse {
                    ck_rv: rv.0,
                }));
            }
        };

    let mut mechanism = match parse_mechanism(req.mechanism) {
        Ok(mechanism) => mechanism,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SignRecoverInitResponse {
                ck_rv: rv.0,
            }));
        }
    };

    // B1: remap object handles embedded in the mechanism parameters;
    // gate each through per-object authz when active (C1).
    if let Err(rv) =
        remap_mechanism_handles(ctx, &ctx_id, req.session_handle, session.0, &mut mechanism).await
    {
        return Ok(Response::new(pkcs11_proxy_ng_proto::SignRecoverInitResponse { ck_rv: rv.0 }));
    }

    // Mechanism policy gate (G3-PR3 Task 3).
    if !mechanism_permitted(ctx, &ctx_id, req.session_handle, mechanism.mechanism_type).await {
        return Ok(Response::new(pkcs11_proxy_ng_proto::SignRecoverInitResponse {
            ck_rv: pkcs11_proxy_ng_types::CkRv::MECHANISM_INVALID.0,
        }));
    }

    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.sign_recover_init(session, &mechanism, key)).await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::SignRecoverInitResponse { ck_rv: ck_rv_only(result) }))
}

pub(crate) async fn sign_recover(
    ctx: &HandlerContext,
    request: Request<pkcs11_proxy_ng_proto::SignRecoverRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SignRecoverResponse>, Status> {
    let ctx_mgr = &ctx.context_manager;
    let backend_ref = &ctx.backend;
    let sanitize_inputs = ctx.sanitize_inputs;
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(session) => session,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SignRecoverResponse {
                ck_rv: rv.0,
                signature: Vec::new(),
            }));
        }
    };

    let data = req.data;
    let data_null_len = req.data_null_len;
    // ADR-0010 sanitize_inputs: validate NULL data pointer before backend call.
    if let Err(rv) = check_sanitize(sanitize_inputs, data_null_len) {
        return Ok(Response::new(pkcs11_proxy_ng_proto::SignRecoverResponse {
            ck_rv: rv.0,
            signature: Vec::new(),
        }));
    }
    let backend = Arc::clone(backend_ref);
    let result =
        spawn_backend(move || backend.sign_recover(session, input_from_wire(&data, data_null_len)))
            .await?;
    let (ck_rv, signature) = ck_result_to_rv(result);
    Ok(Response::new(pkcs11_proxy_ng_proto::SignRecoverResponse {
        ck_rv,
        signature: secret_to_plain(&signature.unwrap_or_default()),
    }))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use pkcs11_proxy_ng_backend::{MockBackend, Pkcs11Backend};
    use pkcs11_proxy_ng_types::*;
    use tonic::Request;

    use crate::config::AuditConfig;
    use crate::server::audit::{AuditSink, spawn_audit_sink};
    use crate::server::context_manager::{ClientContextId, ContextManager};
    use crate::server::grpc_service::HandlerContext;
    use crate::server::handle_map::BackendHandle;

    fn temp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("sign-dp-{}-{}", std::process::id(), tag))
    }

    async fn make_ctx() -> (HandlerContext, ClientContextId, u64) {
        let mock = Arc::new(MockBackend::new(vec![CkSlotId(0)], vec![CkMechanismType::RSA_PKCS]));
        let backend: Arc<dyn Pkcs11Backend> = mock;
        let ctx_mgr = Arc::new(ContextManager::new(Duration::from_secs(300), 0));
        ctx_mgr.register_slot(crate::server::slot_map::BackendSlotId(CkSlotId(0))).await;
        let ctx_id = ctx_mgr.create_context(None).await.unwrap();
        let session_vh = ctx_mgr
            .get_context(&ctx_id, |ctx| {
                ctx.register_session(
                    BackendHandle(1),
                    crate::server::slot_map::BackendSlotId(CkSlotId(0)),
                )
            })
            .await
            .unwrap();
        ctx_mgr.cache_token_info(
            crate::server::slot_map::BackendSlotId(CkSlotId(0)),
            "MockToken".into(),
            "0001".into(),
        );
        let ctx = HandlerContext::for_test(&ctx_mgr, &backend);
        (ctx, ctx_id, session_vh.0)
    }

    fn sign_req(
        ctx_id: &ClientContextId,
        session_handle: u64,
    ) -> pkcs11_proxy_ng_proto::SignRequest {
        pkcs11_proxy_ng_proto::SignRequest {
            client_context_id: ctx_id.0.clone(),
            session_handle,
            data: vec![0u8; 4],
            data_null_len: None,
        }
    }

    fn make_sink(dir: &std::path::Path, data_plane: bool) -> AuditSink {
        let cfg = AuditConfig { dir: Some(dir.to_path_buf()), data_plane, ..Default::default() };
        spawn_audit_sink(&cfg).unwrap().expect("sink")
    }

    fn parse_records(dir: &std::path::Path) -> Vec<pkcs11_proxy_ng_audit::AuditRecord> {
        let content = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap_or_default();
        content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| pkcs11_proxy_ng_audit::record::from_jsonl(l).expect("parse"))
            .collect()
    }

    fn make_audit_dir(dir: &std::path::Path) {
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    /// With `data_plane=true`, a C_Sign completion writes a DataPlane record
    /// with method="C_Sign" and the op's real ck_rv into the audit log.
    #[tokio::test]
    async fn data_plane_true_produces_data_plane_record() {
        let dir = temp_dir("on");
        make_audit_dir(&dir);
        let sink = make_sink(&dir, true);
        let (mut ctx, ctx_id, session_vh) = make_ctx().await;
        ctx.audit = Some(sink.clone());

        let resp = super::sign(&ctx, Request::new(sign_req(&ctx_id, session_vh))).await.unwrap();
        // Any ck_rv is fine (sign_init not called → backend returns error rv);
        // fail-open means the response is always returned.
        let ck_rv = resp.into_inner().ck_rv;

        sink.flush().await.unwrap();

        let records = parse_records(&dir);
        let dp = records.iter().find(|r| r.class == pkcs11_proxy_ng_audit::EventClass::DataPlane);
        assert!(dp.is_some(), "DataPlane record must be written when data_plane=true");
        let dp = dp.unwrap();
        assert_eq!(dp.method, "C_Sign");
        assert_eq!(dp.ck_rv, ck_rv, "record must carry the real ck_rv");

        let report = pkcs11_proxy_ng_audit::verify::verify_dir(&dir, None).unwrap();
        assert!(report.chain_ok, "chain must verify: {report:?}");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// With `data_plane=false`, a C_Sign must NOT write any DataPlane records —
    /// only auth/key-mgmt classes may appear (and none do for a plain sign call).
    #[tokio::test]
    async fn data_plane_false_no_data_plane_record() {
        let dir = temp_dir("off");
        make_audit_dir(&dir);
        let sink = make_sink(&dir, false);
        let (mut ctx, ctx_id, session_vh) = make_ctx().await;
        ctx.audit = Some(sink.clone());

        let _ = super::sign(&ctx, Request::new(sign_req(&ctx_id, session_vh))).await.unwrap();

        sink.flush().await.unwrap();

        let records = parse_records(&dir);
        let has_dp =
            records.iter().any(|r| r.class == pkcs11_proxy_ng_audit::EventClass::DataPlane);
        assert!(!has_dp, "no DataPlane records must appear when data_plane=false");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Fail-open: a saturated sink must NOT cause sign to return a Status error
    /// or change the response — the real ck_rv is always returned.
    #[tokio::test]
    async fn sign_fail_open_saturated_sink() {
        // Build a sink whose channel is already full so every DataPlane emit drops.
        let sink = AuditSink::new_saturated_for_test();
        let (mut ctx, ctx_id, session_vh) = make_ctx().await;
        ctx.audit = Some(sink);

        // sign must return Ok (not a tonic Status error) even with a full channel.
        let resp = super::sign(&ctx, Request::new(sign_req(&ctx_id, session_vh)))
            .await
            .expect("sign must not return a Status error with a saturated audit sink");

        // The ck_rv is whatever the backend returned — never overridden by a drop.
        let _ = resp.into_inner().ck_rv;
    }
}
