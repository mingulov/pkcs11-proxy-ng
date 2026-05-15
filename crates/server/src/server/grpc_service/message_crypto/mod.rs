//! Handlers for PKCS#11 3.0 message-based crypto RPCs.
//!
//! Init/final handlers:
//! - `C_MessageEncryptInit` / `C_MessageEncryptFinal`
//! - `C_MessageDecryptInit` / `C_MessageDecryptFinal`
//! - `C_MessageSignInit` / `C_MessageSignFinal`
//! - `C_MessageVerifyInit` / `C_MessageVerifyFinal`
//!
//! One-shot / begin / next handlers:
//! - `C_EncryptMessage` / `C_EncryptMessageBegin` / `C_EncryptMessageNext`
//! - `C_DecryptMessage` / `C_DecryptMessageBegin` / `C_DecryptMessageNext`
//! - `C_SignMessage` / `C_SignMessageBegin` / `C_SignMessageNext`
//! - `C_VerifyMessage` / `C_VerifyMessageBegin` / `C_VerifyMessageNext`

use std::sync::Arc;

use tonic::{Request, Response, Status};
use tracing::{info, warn};

use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_types::*;

use super::super::context_manager::{ClientContextId, ContextManager};
use super::service_utils::{
    ck_rv_only, parse_mechanism, resolve_session, resolve_session_and_key, spawn_backend,
};

// ---------------------------------------------------------------------------
// Message Encrypt Init (optional mechanism — None means cancel)
// ---------------------------------------------------------------------------

pub(crate) async fn message_encrypt_init(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::MessageEncryptInitRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::MessageEncryptInitResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    if req.mechanism.is_some() {
        // Normal init path: resolve session + key, parse mechanism.
        let (session, key) =
            match resolve_session_and_key(ctx_mgr, &ctx_id, req.session_handle, req.key_handle)
                .await
            {
                Ok(handles) => handles,
                Err(rv) => {
                    return Ok(Response::new(pkcs11_proxy_ng_proto::MessageEncryptInitResponse {
                        ck_rv: rv.0,
                    }));
                }
            };

        let mechanism = match parse_mechanism(req.mechanism) {
            Ok(m) => m,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::MessageEncryptInitResponse {
                    ck_rv: rv.0,
                }));
            }
        };

        let backend = Arc::clone(backend_ref);
        let result =
            spawn_backend(move || backend.message_encrypt_init(session, Some(&mechanism), key))
                .await?;

        let ck_rv = match &result {
            Ok(()) => {
                info!(context_id = %ctx_id.0, "MessageEncryptInit succeeded");
                CkRv::OK.0
            }
            Err(error) => {
                warn!(context_id = %ctx_id.0, rv = error.0, "MessageEncryptInit failed");
                error.0
            }
        };
        Ok(Response::new(pkcs11_proxy_ng_proto::MessageEncryptInitResponse { ck_rv }))
    } else {
        // Cancel path: mechanism absent, key_handle is ignored.
        let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
            Ok(s) => s,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::MessageEncryptInitResponse {
                    ck_rv: rv.0,
                }));
            }
        };

        let backend = Arc::clone(backend_ref);
        let result =
            spawn_backend(move || backend.message_encrypt_init(session, None, CkObjectHandle(0)))
                .await?;

        let ck_rv = match &result {
            Ok(()) => {
                info!(context_id = %ctx_id.0, "MessageEncryptInit (cancel) succeeded");
                CkRv::OK.0
            }
            Err(error) => {
                warn!(context_id = %ctx_id.0, rv = error.0, "MessageEncryptInit (cancel) failed");
                error.0
            }
        };
        Ok(Response::new(pkcs11_proxy_ng_proto::MessageEncryptInitResponse { ck_rv }))
    }
}

// ---------------------------------------------------------------------------
// Message Encrypt Final (session-only cleanup)
// ---------------------------------------------------------------------------

pub(crate) async fn message_encrypt_final(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::MessageEncryptFinalRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::MessageEncryptFinalResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::MessageEncryptFinalResponse {
                ck_rv: rv.0,
            }));
        }
    };

    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.message_encrypt_final(session)).await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::MessageEncryptFinalResponse {
        ck_rv: ck_rv_only(result),
    }))
}

// ---------------------------------------------------------------------------
// Message Decrypt Init (optional mechanism — None means cancel)
// ---------------------------------------------------------------------------

pub(crate) async fn message_decrypt_init(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::MessageDecryptInitRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::MessageDecryptInitResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    if req.mechanism.is_some() {
        // Normal init path: resolve session + key, parse mechanism.
        let (session, key) =
            match resolve_session_and_key(ctx_mgr, &ctx_id, req.session_handle, req.key_handle)
                .await
            {
                Ok(handles) => handles,
                Err(rv) => {
                    return Ok(Response::new(pkcs11_proxy_ng_proto::MessageDecryptInitResponse {
                        ck_rv: rv.0,
                    }));
                }
            };

        let mechanism = match parse_mechanism(req.mechanism) {
            Ok(m) => m,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::MessageDecryptInitResponse {
                    ck_rv: rv.0,
                }));
            }
        };

        let backend = Arc::clone(backend_ref);
        let result =
            spawn_backend(move || backend.message_decrypt_init(session, Some(&mechanism), key))
                .await?;

        let ck_rv = match &result {
            Ok(()) => {
                info!(context_id = %ctx_id.0, "MessageDecryptInit succeeded");
                CkRv::OK.0
            }
            Err(error) => {
                warn!(context_id = %ctx_id.0, rv = error.0, "MessageDecryptInit failed");
                error.0
            }
        };
        Ok(Response::new(pkcs11_proxy_ng_proto::MessageDecryptInitResponse { ck_rv }))
    } else {
        // Cancel path: mechanism absent, key_handle is ignored.
        let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
            Ok(s) => s,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::MessageDecryptInitResponse {
                    ck_rv: rv.0,
                }));
            }
        };

        let backend = Arc::clone(backend_ref);
        let result =
            spawn_backend(move || backend.message_decrypt_init(session, None, CkObjectHandle(0)))
                .await?;

        let ck_rv = match &result {
            Ok(()) => {
                info!(context_id = %ctx_id.0, "MessageDecryptInit (cancel) succeeded");
                CkRv::OK.0
            }
            Err(error) => {
                warn!(context_id = %ctx_id.0, rv = error.0, "MessageDecryptInit (cancel) failed");
                error.0
            }
        };
        Ok(Response::new(pkcs11_proxy_ng_proto::MessageDecryptInitResponse { ck_rv }))
    }
}

// ---------------------------------------------------------------------------
// Message Decrypt Final (session-only cleanup)
// ---------------------------------------------------------------------------

pub(crate) async fn message_decrypt_final(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::MessageDecryptFinalRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::MessageDecryptFinalResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::MessageDecryptFinalResponse {
                ck_rv: rv.0,
            }));
        }
    };

    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.message_decrypt_final(session)).await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::MessageDecryptFinalResponse {
        ck_rv: ck_rv_only(result),
    }))
}

// ---------------------------------------------------------------------------
// Message Sign Init (optional mechanism — None means cancel)
// ---------------------------------------------------------------------------

pub(crate) async fn message_sign_init(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::MessageSignInitRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::MessageSignInitResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    if req.mechanism.is_some() {
        // Normal init path: resolve session + key, parse mechanism.
        let (session, key) =
            match resolve_session_and_key(ctx_mgr, &ctx_id, req.session_handle, req.key_handle)
                .await
            {
                Ok(handles) => handles,
                Err(rv) => {
                    return Ok(Response::new(pkcs11_proxy_ng_proto::MessageSignInitResponse {
                        ck_rv: rv.0,
                    }));
                }
            };

        let mechanism = match parse_mechanism(req.mechanism) {
            Ok(m) => m,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::MessageSignInitResponse {
                    ck_rv: rv.0,
                }));
            }
        };

        let backend = Arc::clone(backend_ref);
        let result =
            spawn_backend(move || backend.message_sign_init(session, Some(&mechanism), key))
                .await?;

        let ck_rv = match &result {
            Ok(()) => {
                info!(context_id = %ctx_id.0, "MessageSignInit succeeded");
                CkRv::OK.0
            }
            Err(error) => {
                warn!(context_id = %ctx_id.0, rv = error.0, "MessageSignInit failed");
                error.0
            }
        };
        Ok(Response::new(pkcs11_proxy_ng_proto::MessageSignInitResponse { ck_rv }))
    } else {
        // Cancel path: mechanism absent, key_handle is ignored.
        let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
            Ok(s) => s,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::MessageSignInitResponse {
                    ck_rv: rv.0,
                }));
            }
        };

        let backend = Arc::clone(backend_ref);
        let result =
            spawn_backend(move || backend.message_sign_init(session, None, CkObjectHandle(0)))
                .await?;

        let ck_rv = match &result {
            Ok(()) => {
                info!(context_id = %ctx_id.0, "MessageSignInit (cancel) succeeded");
                CkRv::OK.0
            }
            Err(error) => {
                warn!(context_id = %ctx_id.0, rv = error.0, "MessageSignInit (cancel) failed");
                error.0
            }
        };
        Ok(Response::new(pkcs11_proxy_ng_proto::MessageSignInitResponse { ck_rv }))
    }
}

// ---------------------------------------------------------------------------
// Message Sign Final (session-only cleanup)
// ---------------------------------------------------------------------------

pub(crate) async fn message_sign_final(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::MessageSignFinalRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::MessageSignFinalResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::MessageSignFinalResponse {
                ck_rv: rv.0,
            }));
        }
    };

    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.message_sign_final(session)).await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::MessageSignFinalResponse { ck_rv: ck_rv_only(result) }))
}

// ---------------------------------------------------------------------------
// Message Verify Init (optional mechanism — None means cancel)
// ---------------------------------------------------------------------------

pub(crate) async fn message_verify_init(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::MessageVerifyInitRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::MessageVerifyInitResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    if req.mechanism.is_some() {
        // Normal init path: resolve session + key, parse mechanism.
        let (session, key) =
            match resolve_session_and_key(ctx_mgr, &ctx_id, req.session_handle, req.key_handle)
                .await
            {
                Ok(handles) => handles,
                Err(rv) => {
                    return Ok(Response::new(pkcs11_proxy_ng_proto::MessageVerifyInitResponse {
                        ck_rv: rv.0,
                    }));
                }
            };

        let mechanism = match parse_mechanism(req.mechanism) {
            Ok(m) => m,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::MessageVerifyInitResponse {
                    ck_rv: rv.0,
                }));
            }
        };

        let backend = Arc::clone(backend_ref);
        let result =
            spawn_backend(move || backend.message_verify_init(session, Some(&mechanism), key))
                .await?;

        let ck_rv = match &result {
            Ok(()) => {
                info!(context_id = %ctx_id.0, "MessageVerifyInit succeeded");
                CkRv::OK.0
            }
            Err(error) => {
                warn!(context_id = %ctx_id.0, rv = error.0, "MessageVerifyInit failed");
                error.0
            }
        };
        Ok(Response::new(pkcs11_proxy_ng_proto::MessageVerifyInitResponse { ck_rv }))
    } else {
        // Cancel path: mechanism absent, key_handle is ignored.
        let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
            Ok(s) => s,
            Err(rv) => {
                return Ok(Response::new(pkcs11_proxy_ng_proto::MessageVerifyInitResponse {
                    ck_rv: rv.0,
                }));
            }
        };

        let backend = Arc::clone(backend_ref);
        let result =
            spawn_backend(move || backend.message_verify_init(session, None, CkObjectHandle(0)))
                .await?;

        let ck_rv = match &result {
            Ok(()) => {
                info!(context_id = %ctx_id.0, "MessageVerifyInit (cancel) succeeded");
                CkRv::OK.0
            }
            Err(error) => {
                warn!(context_id = %ctx_id.0, rv = error.0, "MessageVerifyInit (cancel) failed");
                error.0
            }
        };
        Ok(Response::new(pkcs11_proxy_ng_proto::MessageVerifyInitResponse { ck_rv }))
    }
}

// ---------------------------------------------------------------------------
// Message Verify Final (session-only cleanup)
// ---------------------------------------------------------------------------

pub(crate) async fn message_verify_final(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::MessageVerifyFinalRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::MessageVerifyFinalResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::MessageVerifyFinalResponse {
                ck_rv: rv.0,
            }));
        }
    };

    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.message_verify_final(session)).await?;
    Ok(Response::new(pkcs11_proxy_ng_proto::MessageVerifyFinalResponse {
        ck_rv: ck_rv_only(result),
    }))
}

// ===========================================================================
// One-shot / Begin / Next handlers
// ===========================================================================

// ---------------------------------------------------------------------------
// C_EncryptMessage — one-shot encrypt with parameter_out + ciphertext
// ---------------------------------------------------------------------------

pub(crate) async fn encrypt_message(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::EncryptMessageRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::EncryptMessageResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptMessageResponse {
                ck_rv: rv.0,
                parameter_out: Vec::new(),
                ciphertext: Vec::new(),
            }));
        }
    };

    let mut parameter = req.parameter;
    let aad = req.associated_data;
    let plaintext = req.plaintext;
    let backend = Arc::clone(backend_ref);
    let result =
        spawn_backend(move || backend.encrypt_message(session, &mut parameter, &aad, &plaintext))
            .await?;

    match result {
        Ok((parameter_out, ciphertext)) => {
            Ok(Response::new(pkcs11_proxy_ng_proto::EncryptMessageResponse {
                ck_rv: CkRv::OK.0,
                parameter_out,
                ciphertext,
            }))
        }
        Err(e) => Ok(Response::new(pkcs11_proxy_ng_proto::EncryptMessageResponse {
            ck_rv: e.0,
            parameter_out: Vec::new(),
            ciphertext: Vec::new(),
        })),
    }
}

// ---------------------------------------------------------------------------
// C_EncryptMessageBegin — returns parameter_out only
// ---------------------------------------------------------------------------

pub(crate) async fn encrypt_message_begin(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::EncryptMessageBeginRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::EncryptMessageBeginResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptMessageBeginResponse {
                ck_rv: rv.0,
                parameter_out: Vec::new(),
            }));
        }
    };

    let mut parameter = req.parameter;
    let aad = req.associated_data;
    let backend = Arc::clone(backend_ref);
    let result =
        spawn_backend(move || backend.encrypt_message_begin(session, &mut parameter, &aad)).await?;

    match result {
        Ok(parameter_out) => {
            Ok(Response::new(pkcs11_proxy_ng_proto::EncryptMessageBeginResponse {
                ck_rv: CkRv::OK.0,
                parameter_out,
            }))
        }
        Err(e) => Ok(Response::new(pkcs11_proxy_ng_proto::EncryptMessageBeginResponse {
            ck_rv: e.0,
            parameter_out: Vec::new(),
        })),
    }
}

// ---------------------------------------------------------------------------
// C_EncryptMessageNext — returns parameter_out + ciphertext_part
// ---------------------------------------------------------------------------

pub(crate) async fn encrypt_message_next(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::EncryptMessageNextRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::EncryptMessageNextResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::EncryptMessageNextResponse {
                ck_rv: rv.0,
                parameter_out: Vec::new(),
                ciphertext_part: Vec::new(),
            }));
        }
    };

    let mut parameter = req.parameter;
    let plaintext_part = req.plaintext_part;
    let flags = CkFlags(req.flags);
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.encrypt_message_next(session, &mut parameter, &plaintext_part, flags)
    })
    .await?;

    match result {
        Ok((parameter_out, ciphertext_part)) => {
            Ok(Response::new(pkcs11_proxy_ng_proto::EncryptMessageNextResponse {
                ck_rv: CkRv::OK.0,
                parameter_out,
                ciphertext_part,
            }))
        }
        Err(e) => Ok(Response::new(pkcs11_proxy_ng_proto::EncryptMessageNextResponse {
            ck_rv: e.0,
            parameter_out: Vec::new(),
            ciphertext_part: Vec::new(),
        })),
    }
}

// ---------------------------------------------------------------------------
// C_DecryptMessage — one-shot decrypt with parameter_out + plaintext
// ---------------------------------------------------------------------------

pub(crate) async fn decrypt_message(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::DecryptMessageRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DecryptMessageResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptMessageResponse {
                ck_rv: rv.0,
                parameter_out: Vec::new(),
                plaintext: Vec::new(),
            }));
        }
    };

    let mut parameter = req.parameter;
    let aad = req.associated_data;
    let ciphertext = req.ciphertext;
    let backend = Arc::clone(backend_ref);
    let result =
        spawn_backend(move || backend.decrypt_message(session, &mut parameter, &aad, &ciphertext))
            .await?;

    match result {
        Ok((parameter_out, plaintext)) => {
            Ok(Response::new(pkcs11_proxy_ng_proto::DecryptMessageResponse {
                ck_rv: CkRv::OK.0,
                parameter_out,
                plaintext,
            }))
        }
        Err(e) => Ok(Response::new(pkcs11_proxy_ng_proto::DecryptMessageResponse {
            ck_rv: e.0,
            parameter_out: Vec::new(),
            plaintext: Vec::new(),
        })),
    }
}

// ---------------------------------------------------------------------------
// C_DecryptMessageBegin — returns parameter_out only
// ---------------------------------------------------------------------------

pub(crate) async fn decrypt_message_begin(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::DecryptMessageBeginRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DecryptMessageBeginResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptMessageBeginResponse {
                ck_rv: rv.0,
                parameter_out: Vec::new(),
            }));
        }
    };

    let mut parameter = req.parameter;
    let aad = req.associated_data;
    let backend = Arc::clone(backend_ref);
    let result =
        spawn_backend(move || backend.decrypt_message_begin(session, &mut parameter, &aad)).await?;

    match result {
        Ok(parameter_out) => {
            Ok(Response::new(pkcs11_proxy_ng_proto::DecryptMessageBeginResponse {
                ck_rv: CkRv::OK.0,
                parameter_out,
            }))
        }
        Err(e) => Ok(Response::new(pkcs11_proxy_ng_proto::DecryptMessageBeginResponse {
            ck_rv: e.0,
            parameter_out: Vec::new(),
        })),
    }
}

// ---------------------------------------------------------------------------
// C_DecryptMessageNext — returns parameter_out + plaintext_part
// ---------------------------------------------------------------------------

pub(crate) async fn decrypt_message_next(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::DecryptMessageNextRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::DecryptMessageNextResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::DecryptMessageNextResponse {
                ck_rv: rv.0,
                parameter_out: Vec::new(),
                plaintext_part: Vec::new(),
            }));
        }
    };

    let mut parameter = req.parameter;
    let ciphertext_part = req.ciphertext_part;
    let flags = CkFlags(req.flags);
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.decrypt_message_next(session, &mut parameter, &ciphertext_part, flags)
    })
    .await?;

    match result {
        Ok((parameter_out, plaintext_part)) => {
            Ok(Response::new(pkcs11_proxy_ng_proto::DecryptMessageNextResponse {
                ck_rv: CkRv::OK.0,
                parameter_out,
                plaintext_part,
            }))
        }
        Err(e) => Ok(Response::new(pkcs11_proxy_ng_proto::DecryptMessageNextResponse {
            ck_rv: e.0,
            parameter_out: Vec::new(),
            plaintext_part: Vec::new(),
        })),
    }
}

// ---------------------------------------------------------------------------
// C_SignMessage — one-shot sign with parameter_out + signature
// ---------------------------------------------------------------------------

pub(crate) async fn sign_message(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::SignMessageRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SignMessageResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageResponse {
                ck_rv: rv.0,
                parameter_out: Vec::new(),
                signature: Vec::new(),
            }));
        }
    };

    let mut parameter = req.parameter;
    let data = req.data;
    let backend = Arc::clone(backend_ref);
    let result =
        spawn_backend(move || backend.sign_message(session, &mut parameter, &data)).await?;

    match result {
        Ok((parameter_out, signature)) => {
            Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageResponse {
                ck_rv: CkRv::OK.0,
                parameter_out,
                signature,
            }))
        }
        Err(e) => Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageResponse {
            ck_rv: e.0,
            parameter_out: Vec::new(),
            signature: Vec::new(),
        })),
    }
}

// ---------------------------------------------------------------------------
// C_SignMessageBegin — returns parameter_out only
// ---------------------------------------------------------------------------

pub(crate) async fn sign_message_begin(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::SignMessageBeginRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SignMessageBeginResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageBeginResponse {
                ck_rv: rv.0,
                parameter_out: Vec::new(),
            }));
        }
    };

    let mut parameter = req.parameter;
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.sign_message_begin(session, &mut parameter)).await?;

    match result {
        Ok(parameter_out) => Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageBeginResponse {
            ck_rv: CkRv::OK.0,
            parameter_out,
        })),
        Err(e) => Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageBeginResponse {
            ck_rv: e.0,
            parameter_out: Vec::new(),
        })),
    }
}

// ---------------------------------------------------------------------------
// C_SignMessageNext — returns parameter_out + signature (may be empty)
// ---------------------------------------------------------------------------

pub(crate) async fn sign_message_next(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::SignMessageNextRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::SignMessageNextResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageNextResponse {
                ck_rv: rv.0,
                parameter_out: Vec::new(),
                signature: Vec::new(),
            }));
        }
    };

    let mut parameter = req.parameter;
    let data_part = req.data_part;
    let request_signature = req.request_signature;
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.sign_message_next(session, &mut parameter, &data_part, request_signature)
    })
    .await?;

    match result {
        Ok((parameter_out, signature)) => {
            Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageNextResponse {
                ck_rv: CkRv::OK.0,
                parameter_out,
                signature,
            }))
        }
        Err(e) => Ok(Response::new(pkcs11_proxy_ng_proto::SignMessageNextResponse {
            ck_rv: e.0,
            parameter_out: Vec::new(),
            signature: Vec::new(),
        })),
    }
}

// ---------------------------------------------------------------------------
// C_VerifyMessage — no output buffer, parameter is input-only
// ---------------------------------------------------------------------------

pub(crate) async fn verify_message(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::VerifyMessageRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::VerifyMessageResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageResponse { ck_rv: rv.0 }));
        }
    };

    let parameter = req.parameter;
    let data = req.data;
    let signature = req.signature;
    let backend = Arc::clone(backend_ref);
    let result =
        spawn_backend(move || backend.verify_message(session, &parameter, &data, &signature))
            .await?;

    Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageResponse { ck_rv: ck_rv_only(result) }))
}

// ---------------------------------------------------------------------------
// C_VerifyMessageBegin — no output, parameter is input-only
// ---------------------------------------------------------------------------

pub(crate) async fn verify_message_begin(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::VerifyMessageBeginRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::VerifyMessageBeginResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageBeginResponse {
                ck_rv: rv.0,
                parameter_out: Vec::new(),
            }));
        }
    };

    let parameter = req.parameter;
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || backend.verify_message_begin(session, &parameter)).await?;

    Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageBeginResponse {
        ck_rv: ck_rv_only(result),
        parameter_out: Vec::new(),
    }))
}

// ---------------------------------------------------------------------------
// C_VerifyMessageNext — no output buffer
// ---------------------------------------------------------------------------

pub(crate) async fn verify_message_next(
    ctx_mgr: &Arc<ContextManager>,
    backend_ref: &Arc<dyn Pkcs11Backend>,
    request: Request<pkcs11_proxy_ng_proto::VerifyMessageNextRequest>,
) -> Result<Response<pkcs11_proxy_ng_proto::VerifyMessageNextResponse>, Status> {
    let req = request.into_inner();
    let ctx_id = ClientContextId(req.client_context_id);

    let session = match resolve_session(ctx_mgr, &ctx_id, req.session_handle).await {
        Ok(s) => s,
        Err(rv) => {
            return Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageNextResponse {
                ck_rv: rv.0,
            }));
        }
    };

    let parameter = req.parameter;
    let data_part = req.data_part;
    let is_final = req.is_final;
    let signature = req.signature;
    let backend = Arc::clone(backend_ref);
    let result = spawn_backend(move || {
        backend.verify_message_next(session, &parameter, &data_part, is_final, &signature)
    })
    .await?;

    Ok(Response::new(pkcs11_proxy_ng_proto::VerifyMessageNextResponse {
        ck_rv: ck_rv_only(result),
    }))
}
