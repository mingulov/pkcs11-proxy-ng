use std::sync::Arc;

use crate::config::{AuthConfig, TcpAuthMode};
use pkcs11_proxy_ng_backend::Pkcs11Backend;
use pkcs11_proxy_ng_proto::Pkcs11Proxy;
use pkcs11_proxy_ng_types::*;
use tonic::{Request, Response, Status};

use super::auth::policy::TokenPolicy;
use super::context_manager::ContextManager;

mod async_ops;
mod authorization;
mod byte_output_exact;
mod combined;
mod digest_cipher;
mod general;
mod key_ops;
mod message_crypto;
mod object;
mod parameter_output_exact;
pub mod service_utils;
mod session;
mod session_3x;
mod sign_verify;
mod slot;
mod state_ops;

/// The gRPC service implementation for all PKCS#11 proxy RPCs (ADR-0003).
///
/// Every RPC returns `Ok(Response)` with `ck_rv` in the body. gRPC `Status::Ok`
/// is used whenever a valid `ck_rv` can be returned; transport-level errors use
/// gRPC error codes only for truly unrecoverable situations (e.g. spawn_blocking
/// panic).
#[derive(Clone)]
pub struct Pkcs11ProxyService {
    context_manager: Arc<ContextManager>,
    backend: Arc<dyn Pkcs11Backend>,
    tcp_auth_mode: TcpAuthMode,
    token_policy: Arc<TokenPolicy>,
}

impl Pkcs11ProxyService {
    pub fn new(
        context_manager: Arc<ContextManager>,
        backend: Arc<dyn Pkcs11Backend>,
        tcp_auth_mode: TcpAuthMode,
        token_policy: Arc<TokenPolicy>,
    ) -> Self {
        Self { context_manager, backend, tcp_auth_mode, token_policy }
    }

    pub fn insecure_for_tests(
        context_manager: Arc<ContextManager>,
        backend: Arc<dyn Pkcs11Backend>,
    ) -> Self {
        let token_policy =
            Arc::new(TokenPolicy::from_config(&AuthConfig::default()).expect("default policy"));
        Self::new(context_manager, backend, TcpAuthMode::None, token_policy)
    }
}

pub(super) fn ck_result_to_rv<T>(r: CkResult<T>) -> (u64, Option<T>) {
    match r {
        Ok(v) => (CkRv::OK.0, Some(v)),
        Err(e) => (e.0, None),
    }
}

pub(super) fn convert_template(
    attrs: &[pkcs11_proxy_ng_proto::Attribute],
) -> Result<Vec<CkAttribute>, u64> {
    attrs.iter().map(|a| CkAttribute::try_from(a).map_err(|e| e.0)).collect()
}

pub(super) fn attr_value_to_bytes(v: &CkAttributeValue) -> Vec<u8> {
    match v {
        CkAttributeValue::Bool(b) => {
            if *b {
                vec![1]
            } else {
                vec![0]
            }
        }
        CkAttributeValue::Ulong(u) => u.to_le_bytes().to_vec(),
        CkAttributeValue::Bytes(b) => b.clone(),
        CkAttributeValue::String(s) => s.as_bytes().to_vec(),
    }
}

macro_rules! impl_proxy_service {
    ($(($name:ident, $request:ident, $response:ident, $module:path)),+ $(,)?) => {
        #[tonic::async_trait]
        impl Pkcs11Proxy for Pkcs11ProxyService {
            async fn initialize(
                &self,
                request: Request<pkcs11_proxy_ng_proto::InitializeRequest>,
            ) -> Result<Response<pkcs11_proxy_ng_proto::InitializeResponse>, Status> {
                general::initialize(
                    &self.context_manager,
                    &self.backend,
                    request,
                    self.tcp_auth_mode,
                )
                .await
            }

            async fn get_slot_list(
                &self,
                request: Request<pkcs11_proxy_ng_proto::GetSlotListRequest>,
            ) -> Result<Response<pkcs11_proxy_ng_proto::GetSlotListResponse>, Status> {
                slot::get_slot_list_with_policy(
                    &self.context_manager,
                    &self.backend,
                    self.token_policy.as_ref(),
                    request,
                )
                .await
            }

            async fn get_slot_info(
                &self,
                request: Request<pkcs11_proxy_ng_proto::GetSlotInfoRequest>,
            ) -> Result<Response<pkcs11_proxy_ng_proto::GetSlotInfoResponse>, Status> {
                slot::get_slot_info_with_policy(
                    &self.context_manager,
                    &self.backend,
                    self.token_policy.as_ref(),
                    request,
                )
                .await
            }

            async fn get_token_info(
                &self,
                request: Request<pkcs11_proxy_ng_proto::GetTokenInfoRequest>,
            ) -> Result<Response<pkcs11_proxy_ng_proto::GetTokenInfoResponse>, Status> {
                slot::get_token_info_with_policy(
                    &self.context_manager,
                    &self.backend,
                    self.token_policy.as_ref(),
                    request,
                )
                .await
            }

            async fn get_mechanism_list(
                &self,
                request: Request<pkcs11_proxy_ng_proto::GetMechanismListRequest>,
            ) -> Result<Response<pkcs11_proxy_ng_proto::GetMechanismListResponse>, Status> {
                slot::get_mechanism_list_with_policy(
                    &self.context_manager,
                    &self.backend,
                    self.token_policy.as_ref(),
                    request,
                )
                .await
            }

            async fn get_mechanism_info(
                &self,
                request: Request<pkcs11_proxy_ng_proto::GetMechanismInfoRequest>,
            ) -> Result<Response<pkcs11_proxy_ng_proto::GetMechanismInfoResponse>, Status> {
                slot::get_mechanism_info_with_policy(
                    &self.context_manager,
                    &self.backend,
                    self.token_policy.as_ref(),
                    request,
                )
                .await
            }

            async fn open_session(
                &self,
                request: Request<pkcs11_proxy_ng_proto::OpenSessionRequest>,
            ) -> Result<Response<pkcs11_proxy_ng_proto::OpenSessionResponse>, Status> {
                session::open_session_with_policy(
                    &self.context_manager,
                    &self.backend,
                    self.token_policy.as_ref(),
                    request,
                )
                .await
            }

            async fn close_all_sessions(
                &self,
                request: Request<pkcs11_proxy_ng_proto::CloseAllSessionsRequest>,
            ) -> Result<Response<pkcs11_proxy_ng_proto::CloseAllSessionsResponse>, Status> {
                session::close_all_sessions_with_policy(
                    &self.context_manager,
                    &self.backend,
                    self.token_policy.as_ref(),
                    request,
                )
                .await
            }

            async fn init_token(
                &self,
                request: Request<pkcs11_proxy_ng_proto::InitTokenRequest>,
            ) -> Result<Response<pkcs11_proxy_ng_proto::InitTokenResponse>, Status> {
                session::init_token_with_policy(
                    &self.context_manager,
                    &self.backend,
                    self.token_policy.as_ref(),
                    request,
                )
                .await
            }

            $(
                async fn $name(
                    &self,
                    request: Request<pkcs11_proxy_ng_proto::$request>,
                ) -> Result<Response<pkcs11_proxy_ng_proto::$response>, Status> {
                    $module(&self.context_manager, &self.backend, request).await
                }
            )+
        }
    };
}

impl_proxy_service!(
    (finalize, FinalizeRequest, FinalizeResponse, general::finalize),
    (get_info, GetInfoRequest, GetInfoResponse, general::get_info),
    (close_session, CloseSessionRequest, CloseSessionResponse, session::close_session),
    (get_session_info, GetSessionInfoRequest, GetSessionInfoResponse, session::get_session_info),
    (login, LoginRequest, LoginResponse, session::login),
    (logout, LogoutRequest, LogoutResponse, session::logout),
    (init_pin, InitPinRequest, InitPinResponse, session::init_pin),
    (set_pin, SetPinRequest, SetPinResponse, session::set_pin),
    // Legacy parallel function status (PKCS#11 2.40)
    (
        get_function_status,
        GetFunctionStatusRequest,
        GetFunctionStatusResponse,
        session::get_function_status
    ),
    (cancel_function, CancelFunctionRequest, CancelFunctionResponse, session::cancel_function),
    (find_objects_init, FindObjectsInitRequest, FindObjectsInitResponse, object::find_objects_init),
    (find_objects, FindObjectsRequest, FindObjectsResponse, object::find_objects),
    (
        find_objects_final,
        FindObjectsFinalRequest,
        FindObjectsFinalResponse,
        object::find_objects_final
    ),
    (
        get_attribute_value,
        GetAttributeValueRequest,
        GetAttributeValueResponse,
        object::get_attribute_value
    ),
    (
        get_attribute_value_exact,
        GetAttributeValueExactRequest,
        GetAttributeValueExactResponse,
        object::get_attribute_value_exact
    ),
    (create_object, CreateObjectRequest, CreateObjectResponse, object::create_object),
    (copy_object, CopyObjectRequest, CopyObjectResponse, object::copy_object),
    (destroy_object, DestroyObjectRequest, DestroyObjectResponse, object::destroy_object),
    (get_object_size, GetObjectSizeRequest, GetObjectSizeResponse, object::get_object_size),
    (
        set_attribute_value,
        SetAttributeValueRequest,
        SetAttributeValueResponse,
        object::set_attribute_value
    ),
    (sign_init, SignInitRequest, SignInitResponse, sign_verify::sign_init),
    (sign, SignRequest, SignResponse, sign_verify::sign),
    (sign_update, SignUpdateRequest, SignUpdateResponse, sign_verify::sign_update),
    (sign_final, SignFinalRequest, SignFinalResponse, sign_verify::sign_final),
    (verify_init, VerifyInitRequest, VerifyInitResponse, sign_verify::verify_init),
    (verify, VerifyRequest, VerifyResponse, sign_verify::verify),
    (verify_update, VerifyUpdateRequest, VerifyUpdateResponse, sign_verify::verify_update),
    (verify_final, VerifyFinalRequest, VerifyFinalResponse, sign_verify::verify_final),
    (
        sign_recover_init,
        SignRecoverInitRequest,
        SignRecoverInitResponse,
        sign_verify::sign_recover_init
    ),
    (sign_recover, SignRecoverRequest, SignRecoverResponse, sign_verify::sign_recover),
    (
        verify_recover_init,
        VerifyRecoverInitRequest,
        VerifyRecoverInitResponse,
        sign_verify::verify_recover_init
    ),
    (verify_recover, VerifyRecoverRequest, VerifyRecoverResponse, sign_verify::verify_recover),
    (digest_init, DigestInitRequest, DigestInitResponse, digest_cipher::digest_init),
    (digest, DigestRequest, DigestResponse, digest_cipher::digest),
    (digest_update, DigestUpdateRequest, DigestUpdateResponse, digest_cipher::digest_update),
    (digest_key, DigestKeyRequest, DigestKeyResponse, digest_cipher::digest_key),
    (digest_final, DigestFinalRequest, DigestFinalResponse, digest_cipher::digest_final),
    (encrypt_init, EncryptInitRequest, EncryptInitResponse, digest_cipher::encrypt_init),
    (encrypt, EncryptRequest, EncryptResponse, digest_cipher::encrypt),
    (encrypt_update, EncryptUpdateRequest, EncryptUpdateResponse, digest_cipher::encrypt_update),
    (encrypt_final, EncryptFinalRequest, EncryptFinalResponse, digest_cipher::encrypt_final),
    (decrypt_init, DecryptInitRequest, DecryptInitResponse, digest_cipher::decrypt_init),
    (decrypt, DecryptRequest, DecryptResponse, digest_cipher::decrypt),
    (decrypt_update, DecryptUpdateRequest, DecryptUpdateResponse, digest_cipher::decrypt_update),
    (decrypt_final, DecryptFinalRequest, DecryptFinalResponse, digest_cipher::decrypt_final),
    (
        generate_key_pair,
        GenerateKeyPairRequest,
        GenerateKeyPairResponse,
        key_ops::generate_key_pair
    ),
    (generate_key, GenerateKeyRequest, GenerateKeyResponse, key_ops::generate_key),
    (derive_key, DeriveKeyRequest, DeriveKeyResponse, key_ops::derive_key),
    (wrap_key, WrapKeyRequest, WrapKeyResponse, key_ops::wrap_key),
    (unwrap_key, UnwrapKeyRequest, UnwrapKeyResponse, key_ops::unwrap_key),
    (generate_random, GenerateRandomRequest, GenerateRandomResponse, state_ops::generate_random),
    (
        wait_for_slot_event,
        WaitForSlotEventRequest,
        WaitForSlotEventResponse,
        state_ops::wait_for_slot_event
    ),
    (
        get_operation_state,
        GetOperationStateRequest,
        GetOperationStateResponse,
        state_ops::get_operation_state
    ),
    (
        set_operation_state,
        SetOperationStateRequest,
        SetOperationStateResponse,
        state_ops::set_operation_state
    ),
    (seed_random, SeedRandomRequest, SeedRandomResponse, state_ops::seed_random),
    (
        digest_encrypt_update,
        DigestEncryptUpdateRequest,
        DigestEncryptUpdateResponse,
        combined::digest_encrypt_update
    ),
    (
        decrypt_digest_update,
        DecryptDigestUpdateRequest,
        DecryptDigestUpdateResponse,
        combined::decrypt_digest_update
    ),
    (
        sign_encrypt_update,
        SignEncryptUpdateRequest,
        SignEncryptUpdateResponse,
        combined::sign_encrypt_update
    ),
    (
        decrypt_verify_update,
        DecryptVerifyUpdateRequest,
        DecryptVerifyUpdateResponse,
        combined::decrypt_verify_update
    ),
    // PKCS#11 3.0 — Session extensions
    (login_user, LoginUserRequest, LoginUserResponse, session_3x::login_user),
    (session_cancel, SessionCancelRequest, SessionCancelResponse, session_3x::session_cancel),
    // PKCS#11 3.0 — Message-based encryption
    (
        message_encrypt_init,
        MessageEncryptInitRequest,
        MessageEncryptInitResponse,
        message_crypto::message_encrypt_init
    ),
    (
        encrypt_message,
        EncryptMessageRequest,
        EncryptMessageResponse,
        message_crypto::encrypt_message
    ),
    (
        encrypt_message_begin,
        EncryptMessageBeginRequest,
        EncryptMessageBeginResponse,
        message_crypto::encrypt_message_begin
    ),
    (
        encrypt_message_next,
        EncryptMessageNextRequest,
        EncryptMessageNextResponse,
        message_crypto::encrypt_message_next
    ),
    (
        message_encrypt_final,
        MessageEncryptFinalRequest,
        MessageEncryptFinalResponse,
        message_crypto::message_encrypt_final
    ),
    // PKCS#11 3.0 — Message-based decryption
    (
        message_decrypt_init,
        MessageDecryptInitRequest,
        MessageDecryptInitResponse,
        message_crypto::message_decrypt_init
    ),
    (
        decrypt_message,
        DecryptMessageRequest,
        DecryptMessageResponse,
        message_crypto::decrypt_message
    ),
    (
        decrypt_message_begin,
        DecryptMessageBeginRequest,
        DecryptMessageBeginResponse,
        message_crypto::decrypt_message_begin
    ),
    (
        decrypt_message_next,
        DecryptMessageNextRequest,
        DecryptMessageNextResponse,
        message_crypto::decrypt_message_next
    ),
    (
        message_decrypt_final,
        MessageDecryptFinalRequest,
        MessageDecryptFinalResponse,
        message_crypto::message_decrypt_final
    ),
    // PKCS#11 3.0 — Message-based signing
    (
        message_sign_init,
        MessageSignInitRequest,
        MessageSignInitResponse,
        message_crypto::message_sign_init
    ),
    (sign_message, SignMessageRequest, SignMessageResponse, message_crypto::sign_message),
    (
        sign_message_begin,
        SignMessageBeginRequest,
        SignMessageBeginResponse,
        message_crypto::sign_message_begin
    ),
    (
        sign_message_next,
        SignMessageNextRequest,
        SignMessageNextResponse,
        message_crypto::sign_message_next
    ),
    (
        message_sign_final,
        MessageSignFinalRequest,
        MessageSignFinalResponse,
        message_crypto::message_sign_final
    ),
    // PKCS#11 3.0 — Message-based verification
    (
        message_verify_init,
        MessageVerifyInitRequest,
        MessageVerifyInitResponse,
        message_crypto::message_verify_init
    ),
    (verify_message, VerifyMessageRequest, VerifyMessageResponse, message_crypto::verify_message),
    (
        verify_message_begin,
        VerifyMessageBeginRequest,
        VerifyMessageBeginResponse,
        message_crypto::verify_message_begin
    ),
    (
        verify_message_next,
        VerifyMessageNextRequest,
        VerifyMessageNextResponse,
        message_crypto::verify_message_next
    ),
    (
        message_verify_final,
        MessageVerifyFinalRequest,
        MessageVerifyFinalResponse,
        message_crypto::message_verify_final
    ),
    // PKCS#11 3.2 — KEM
    (encapsulate_key, EncapsulateKeyRequest, EncapsulateKeyResponse, key_ops::encapsulate_key),
    (decapsulate_key, DecapsulateKeyRequest, DecapsulateKeyResponse, key_ops::decapsulate_key),
    // PKCS#11 3.2 — Verify signature
    (
        verify_signature_init,
        VerifySignatureInitRequest,
        VerifySignatureInitResponse,
        sign_verify::verify_signature_init
    ),
    (
        verify_signature,
        VerifySignatureRequest,
        VerifySignatureResponse,
        sign_verify::verify_signature
    ),
    (
        verify_signature_update,
        VerifySignatureUpdateRequest,
        VerifySignatureUpdateResponse,
        sign_verify::verify_signature_update
    ),
    (
        verify_signature_final,
        VerifySignatureFinalRequest,
        VerifySignatureFinalResponse,
        sign_verify::verify_signature_final
    ),
    // PKCS#11 3.2 — Authenticated wrap
    (
        wrap_key_authenticated,
        WrapKeyAuthenticatedRequest,
        WrapKeyAuthenticatedResponse,
        key_ops::wrap_key_authenticated
    ),
    (
        unwrap_key_authenticated,
        UnwrapKeyAuthenticatedRequest,
        UnwrapKeyAuthenticatedResponse,
        key_ops::unwrap_key_authenticated
    ),
    // PKCS#11 3.2 — Async
    (async_complete, AsyncCompleteRequest, AsyncCompleteResponse, async_ops::async_complete),
    (async_get_id, AsyncGetIdRequest, AsyncGetIdResponse, async_ops::async_get_id),
    (async_join, AsyncJoinRequest, AsyncJoinResponse, async_ops::async_join),
    // PKCS#11 3.2 — Validation
    (
        get_session_validation_flags,
        GetSessionValidationFlagsRequest,
        GetSessionValidationFlagsResponse,
        session_3x::get_session_validation_flags
    ),
    (
        get_backend_interfaces,
        GetBackendInterfacesRequest,
        GetBackendInterfacesResponse,
        general::get_backend_interfaces
    ),
    // Track B: Exact byte-output RPC
    (
        byte_output_exact,
        ByteOutputExactRequest,
        ByteOutputExactResponse,
        byte_output_exact::byte_output_exact
    ),
    // Track C: Exact parameter-output RPC
    (
        parameter_output_exact,
        ParameterOutputExactRequest,
        ParameterOutputExactResponse,
        parameter_output_exact::parameter_output_exact
    ),
    // Track C Task 2: Exact encapsulate-key RPC
    (
        encapsulate_key_exact,
        EncapsulateKeyExactRequest,
        EncapsulateKeyExactResponse,
        key_ops::encapsulate_key_exact
    ),
);
