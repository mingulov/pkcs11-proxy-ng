use crate::server::slot_map::BackendSlotId;
use std::sync::Arc;

use tonic::{Request, Response, Status};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::CkRv;

use super::super::super::auth::policy::TokenPolicy;
use super::super::super::context_manager::{ClientContextId, ContextManager};
use super::super::authorization::slot_is_authorized;
use super::super::service_utils::{current_context_operation_guard, spawn_task};

/// Bound for a `CKF_DONT_BLOCK` backend wait (W1-L6-10). A correct provider
/// answers a nonblocking poll in microseconds; only a faulty one parks it.
/// Past this grace the daemon reports `CKR_NO_EVENT` and abandons the
/// parked call instead of blocking a poll that must never block.
const NONBLOCKING_WAIT_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

fn no_event() -> Response<pkcs11_proxy_ng_proto::WaitForSlotEventResponse> {
    Response::new(pkcs11_proxy_ng_proto::WaitForSlotEventResponse {
        ck_rv: CkRv::NO_EVENT.0,
        slot_id: 0,
    })
}

pub(super) async fn wait_for_slot_event(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    token_policy: &TokenPolicy,
    request: Request<pkcs11_proxy_ng_proto::WaitForSlotEventRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::WaitForSlotEventResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let context: Option<()> = ctx_mgr.get_context(&ctx_id, |_| ()).await;
    if context.is_none() {
        return Ok(Response::new(pkcs11_proxy_ng_proto::WaitForSlotEventResponse {
            ck_rv: CkRv::CRYPTOKI_NOT_INITIALIZED.0,
            slot_id: 0,
        }));
    }

    // W1-L6-10: slot waits bypass spawn_backend entirely — they hold NO
    // breaker slot and take NO request timeout. A blocking wait
    // legitimately outlives request_timeout (native modules block
    // indefinitely), so routing it through the breaker burned a stuck
    // slot per slow wait and let repeated waits trip the global
    // breaker. Floods are bounded instead by the transport (L6-20) and
    // per-connection admission (L7-28) layers. The dispatch operation
    // guard still travels into the blocking task so a parked wait keeps
    // its context unreapable, exactly as before.
    let flags = req.flags;
    let dont_block = flags & cryptoki_sys::CKF_DONT_BLOCK as u64 != 0;
    let backend = backend_ref.clone();
    let operation_guard = current_context_operation_guard();
    let result = if dont_block {
        // Respect DONT_BLOCK: a nonblocking poll must never block. A
        // correct provider answers at once; if a faulty one still
        // hasn't answered within the grace, report NO_EVENT and abandon
        // the parked call — any real event surfaces on the next poll.
        let task = spawn_task(move || {
            let _operation_guard = operation_guard;
            backend.wait_for_slot_event(flags)
        });
        match tokio::time::timeout(NONBLOCKING_WAIT_GRACE, task).await {
            Ok(result) => result?,
            Err(_elapsed) => {
                tracing::warn!(
                    grace_secs = NONBLOCKING_WAIT_GRACE.as_secs(),
                    "DONT_BLOCK slot wait still parked past the grace; \
                     reporting NO_EVENT (faulty provider)"
                );
                Err(CkRv::NO_EVENT)
            }
        }
    } else {
        spawn_task(move || {
            let _operation_guard = operation_guard;
            backend.wait_for_slot_event(flags)
        })
        .await?
    };

    let backend_slot = match result {
        Ok(backend_slot) => BackendSlotId(backend_slot),
        Err(error) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::WaitForSlotEventResponse {
                ck_rv: error.0,
                slot_id: 0,
            }));
        }
    };

    // Never leak the raw backend slot id: an event for a slot this client has
    // no virtual mapping for is reported as no-event (M13).
    let Some(virtual_slot) = ctx_mgr.to_virtual_slot(backend_slot).await else {
        return Ok(no_event());
    };

    // Suppress events for tokens this client is not authorized to see, so the
    // insertion/removal of a token outside its policy is not disclosed (M13).
    // An unauthenticated context bypasses the policy (slot_is_authorized → true),
    // preserving prior behavior; any policy denial or token-info error fails
    // closed to no-event rather than leaking the slot.
    match slot_is_authorized(ctx_mgr, backend_ref, token_policy, &ctx_id, backend_slot).await? {
        Ok(true) => Ok(Response::new(pkcs11_proxy_ng_proto::WaitForSlotEventResponse {
            ck_rv: CkRv::OK.0,
            slot_id: virtual_slot.0,
        })),
        // Ownership §"Slot-event scope": a policy follow-up refused by a
        // sealed backend (or a context that disappeared mid-call) answers
        // local NOT_INITIALIZED with no slot output — the wait's actual OK
        // observation is retained, never published as an event and never
        // downgraded to NO_EVENT. Every other denial or backend error
        // still suppresses to no-event.
        Err(error) if error == CkRv::CRYPTOKI_NOT_INITIALIZED => {
            Ok(Response::new(pkcs11_proxy_ng_proto::WaitForSlotEventResponse {
                ck_rv: CkRv::CRYPTOKI_NOT_INITIALIZED.0,
                slot_id: 0,
            }))
        }
        _ => Ok(no_event()),
    }
}
