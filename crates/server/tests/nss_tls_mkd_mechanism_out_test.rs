// W1-L12-03: test diagnostics (skip notices, progress, summaries) go to
// stderr by design; the workspace lint table denies this sink elsewhere.
#![allow(clippy::print_stderr)]
//! W1-C5-01 real-backend proof: SSL3 master-key derive through NSS
//! softokn delivers the provider-written version in `mechanism_out`
//! end to end (client → gRPC → server → FFI → NSS → back).
//!
//! NSS is the only locally available provider implementing an affected
//! shape (`CKM_SSL3_MASTER_KEY_DERIVE`); neither SoftHSM2 nor NSS
//! implements `CKM_TLS_PRF`/`CKM_WTLS_PRF`, so those two shapes are
//! proven by the stub-provider derive-path tests in
//! `crates/backend/src/ffi/key_state_ops.rs` (same
//! `output_params()` code path, provider-style writes).
//!
//! Run with:
//!
//! ```text
//! cargo test -p pkcs11-proxy-ng --test nss_tls_mkd_mechanism_out_test -- --ignored
//! ```

mod support;

use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::{
    CkAttribute, CkAttributeType, CkAttributeValue, CkKeyType, CkMechanism, CkMechanismParams,
    CkMechanismType, CkObjectClass, CkObjectHandle, CkSessionHandle, Ssl3MasterKeyDeriveParams,
    SslRandomData,
};
use support::{
    CKA_DERIVE, DaemonHarness, ProviderFixture, ensure_user_token, initialized_client,
    open_user_session,
};

fn attr(attr_type: CkAttributeType, value: CkAttributeValue) -> CkAttribute {
    CkAttribute { attr_type, value: Some(value) }
}

/// 48-byte pre-master secret base key: prefer `C_GenerateKey` (NULL
/// version params); fall back to `C_CreateObject` with an explicit
/// version-prefixed value when NSS requires mechanism params.
async fn premaster_base_key(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
) -> Result<CkObjectHandle, String> {
    let gen_template = vec![
        attr(CkAttributeType::CLASS, CkAttributeValue::Ulong(CkObjectClass::SECRET_KEY.0)),
        attr(CkAttributeType::KEY_TYPE, CkAttributeValue::Ulong(CkKeyType::GENERIC_SECRET.0)),
        attr(CkAttributeType::VALUE_LEN, CkAttributeValue::Ulong(48)),
        attr(CkAttributeType::TOKEN, CkAttributeValue::Bool(false)),
        attr(CKA_DERIVE, CkAttributeValue::Bool(true)),
    ];
    let gen_mech =
        CkMechanism { mechanism_type: CkMechanismType::SSL3_PRE_MASTER_KEY_GEN, params: None };
    match client.generate_key(session, &gen_mech, Some(&gen_template)).await {
        Ok(handle) => return Ok(handle),
        Err(rv) => eprintln!("PMSA C_GenerateKey failed ({rv}); trying C_CreateObject"),
    }

    let mut value = vec![0x42u8; 48];
    value[0] = 3; // client version major
    value[1] = 1; // client version minor (TLS 1.0)
    let create_template = vec![
        attr(CkAttributeType::CLASS, CkAttributeValue::Ulong(CkObjectClass::SECRET_KEY.0)),
        attr(CkAttributeType::KEY_TYPE, CkAttributeValue::Ulong(CkKeyType::GENERIC_SECRET.0)),
        attr(CkAttributeType::VALUE, CkAttributeValue::Bytes(value.into())),
        attr(CkAttributeType::TOKEN, CkAttributeValue::Bool(false)),
        attr(CKA_DERIVE, CkAttributeValue::Bool(true)),
    ];
    client
        .create_object(session, Some(&create_template))
        .await
        .map_err(|rv| format!("PMSA C_CreateObject failed: {rv}"))
}

#[tokio::test]
#[ignore] // requires NSS softokn
async fn nss_ssl3_master_key_derive_reports_negotiated_version() -> Result<(), String> {
    let fixture = ProviderFixture::nss_softokn().await?;
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;
    let slot = ensure_user_token(&mut client, &fixture).await?;
    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;

    let pmsa = premaster_base_key(&mut client, session).await?;
    eprintln!("PMSA base key: {pmsa:?}");

    let mech = CkMechanism {
        mechanism_type: CkMechanismType::SSL3_MASTER_KEY_DERIVE,
        params: Some(CkMechanismParams::Ssl3MasterKeyDerive(Ssl3MasterKeyDeriveParams {
            random_info: SslRandomData {
                client_random: vec![0x11; 32],
                server_random: vec![0x22; 32],
            },
            version_major: 3,
            version_minor: 0,
        })),
    };
    let derive_template = vec![
        attr(CkAttributeType::CLASS, CkAttributeValue::Ulong(CkObjectClass::SECRET_KEY.0)),
        attr(CkAttributeType::KEY_TYPE, CkAttributeValue::Ulong(CkKeyType::GENERIC_SECRET.0)),
        attr(CkAttributeType::TOKEN, CkAttributeValue::Bool(false)),
        attr(CkAttributeType::SENSITIVE, CkAttributeValue::Bool(false)),
        attr(CkAttributeType::EXTRACTABLE, CkAttributeValue::Bool(true)),
    ];
    let (handle, mech_out) = client
        .derive_key_with_mechanism_out(session, &mech, pmsa, Some(&derive_template))
        .await
        .map_err(|rv| format!("C_DeriveKey failed: CKR 0x{:08X}", rv.0))?;
    eprintln!("derived master key: {handle:?}; mechanism_out: {mech_out:?}");

    match mech_out {
        Some(CkMechanismParams::Ssl3MasterKeyDerive(p)) => {
            // NSS reports the pre-master-embedded client version {3,1}
            // — NOT our requested {3,0} — proving this is genuinely
            // provider-written output, not an input echo.
            assert_eq!(p.version_major, 3, "NSS writes the SSL major version");
            assert_eq!(p.version_minor, 1, "NSS reports the PMSA-embedded version");
            assert_eq!(p.random_info.client_random, vec![0x11; 32]);
            assert_eq!(p.random_info.server_random, vec![0x22; 32]);
        }
        other => panic!("expected SSL3-MKD mechanism_out, got {other:?}"),
    }

    client.logout(session).await.map_err(|rv| rv.to_string())?;
    client.close_session(session).await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}
