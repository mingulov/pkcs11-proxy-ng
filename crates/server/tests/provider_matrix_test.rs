//! Optional provider-matrix coverage for non-SoftHSM backends.
//!
//! These tests are env-driven because NSS softokn and Kryoptic provisioning is
//! deployment-specific. The matrix scripts enable them when the required env
//! vars are present.

mod support;

use pkcs11_proxy_ng_types::{CkMechanism, CkMechanismType, CkRv};
use support::{
    DaemonHarness, ProviderFixture, SkipReason, ensure_user_token, find_objects_by_id,
    find_objects_by_label, generate_named_rsa_key_pair, initialized_client, open_public_session,
    open_user_session, rsa_encrypt_and_decrypt, rsa_oaep_encrypt, rsa_pss_sign,
    rsa_sign_and_verify, sha256_digest_matches, supports_mechanism,
};

#[derive(Clone, Copy)]
struct MechanismProbe {
    name: &'static str,
    mechanism: CkMechanismType,
}

const CAPABILITY_PROBES: &[MechanismProbe] = &[
    MechanismProbe { name: "CKM_SHA256", mechanism: CkMechanismType::SHA256 },
    MechanismProbe { name: "CKM_RSA_PKCS", mechanism: CkMechanismType::RSA_PKCS },
    MechanismProbe {
        name: "CKM_RSA_PKCS_KEY_PAIR_GEN",
        mechanism: CkMechanismType::RSA_PKCS_KEY_PAIR_GEN,
    },
    MechanismProbe { name: "CKM_RSA_PKCS_PSS", mechanism: CkMechanismType::RSA_PKCS_PSS },
    MechanismProbe { name: "CKM_RSA_PKCS_OAEP", mechanism: CkMechanismType::RSA_PKCS_OAEP },
    MechanismProbe { name: "CKM_AES_CBC", mechanism: CkMechanismType::AES_CBC },
    MechanismProbe { name: "CKM_AES_GCM", mechanism: CkMechanismType::AES_GCM },
    MechanismProbe { name: "CKM_ECDH1_DERIVE", mechanism: CkMechanismType::ECDH1_DERIVE },
];

const UNSUPPORTED_PROBES: &[MechanismProbe] = &[
    MechanismProbe { name: "vendor probe 0x8FFFFF00", mechanism: CkMechanismType(0x8FFF_FF00) },
    MechanismProbe { name: "vendor probe 0x8FFFFF01", mechanism: CkMechanismType(0x8FFF_FF01) },
    MechanismProbe { name: "vendor probe 0x8FFFFF02", mechanism: CkMechanismType(0x8FFF_FF02) },
];

async fn optional_nss_fixture() -> Result<Option<ProviderFixture>, String> {
    if std::env::var_os("PKCS11_PROXY_NSS_MODULE").is_some() {
        match ProviderFixture::nss_from_env().await {
            Ok(fixture) => Ok(Some(fixture)),
            Err(_reason) => {
                record_skip!(SkipReason::ProviderMissing("NSS softokn (env-configured)"));
                Ok(None)
            }
        }
    } else {
        match ProviderFixture::nss_softokn().await {
            Ok(fixture) => Ok(Some(fixture)),
            Err(_reason) => {
                record_skip!(SkipReason::ProviderMissing("NSS softokn (auto-detected)"));
                Ok(None)
            }
        }
    }
}

async fn optional_kryoptic_fixture() -> Result<Option<ProviderFixture>, String> {
    match ProviderFixture::kryoptic_from_env().await {
        Ok(fixture) => Ok(Some(fixture)),
        Err(_reason) => {
            record_skip!(SkipReason::ProviderMissing("Kryoptic (env-configured)"));
            Ok(None)
        }
    }
}

fn first_unadvertised_probe(mechanisms: &[CkMechanismType]) -> Result<MechanismProbe, String> {
    UNSUPPORTED_PROBES
        .iter()
        .copied()
        .find(|probe| !mechanisms.contains(&probe.mechanism))
        .ok_or_else(|| "all unsupported probe mechanisms were unexpectedly advertised".to_string())
}

fn expect_mechanism_invalid<T>(
    provider: &str,
    operation: &str,
    probe: MechanismProbe,
    result: Result<T, CkRv>,
) -> Result<(), String> {
    match result {
        Err(CkRv::MECHANISM_INVALID) => Ok(()),
        Err(rv) => Err(format!(
            "{provider}: {operation} for unadvertised {} returned {rv}, expected CKR_MECHANISM_INVALID",
            probe.name
        )),
        Ok(_) => Err(format!(
            "{provider}: {operation} for unadvertised {} unexpectedly succeeded",
            probe.name
        )),
    }
}

async fn run_optional_backend_smoke(fixture: ProviderFixture) -> Result<(), String> {
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;

    let info = client.get_info().await.map_err(|rv| rv.to_string())?;
    assert!(!info.library_description.trim().is_empty());

    let slot = ensure_user_token(&mut client, &fixture).await?;
    let _slot_info = client.get_slot_info(slot).await.map_err(|rv| rv.to_string())?;
    let _token_info = client.get_token_info(slot).await.map_err(|rv| rv.to_string())?;
    let _mechanisms = client.get_mechanism_list(slot).await.map_err(|rv| rv.to_string())?;

    let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;
    let random = client.generate_random(session, 16).await.map_err(|rv| rv.to_string())?;
    assert_eq!(random.len(), 16);

    let payload = format!("provider-matrix-{}", fixture.name);
    if supports_mechanism(&mut client, slot, CkMechanismType::SHA256).await? {
        sha256_digest_matches(&mut client, session, payload.as_bytes()).await?;
    }

    if supports_mechanism(&mut client, slot, CkMechanismType::RSA_PKCS_KEY_PAIR_GEN).await?
        && supports_mechanism(&mut client, slot, CkMechanismType::RSA_PKCS).await?
    {
        let pair = generate_named_rsa_key_pair(&mut client, session, fixture.name, true).await?;
        rsa_sign_and_verify(
            &mut client,
            session,
            pair.private_key,
            pair.public_key,
            payload.as_bytes(),
        )
        .await?;
        let decrypted = rsa_encrypt_and_decrypt(
            &mut client,
            session,
            pair.public_key,
            pair.private_key,
            payload.as_bytes(),
        )
        .await?;
        assert_eq!(decrypted, payload.as_bytes());

        if supports_mechanism(&mut client, slot, CkMechanismType::RSA_PKCS_PSS).await? {
            rsa_pss_sign(&mut client, session, pair.private_key, payload.as_bytes()).await?;
        }

        if supports_mechanism(&mut client, slot, CkMechanismType::RSA_PKCS_OAEP).await? {
            rsa_oaep_encrypt(&mut client, session, pair.public_key, payload.as_bytes()).await?;
        }

        client.close_session(session).await.map_err(|rv| rv.to_string())?;

        let session = open_user_session(&mut client, slot, &fixture.user_pin, true).await?;
        let found_public = find_objects_by_label(&mut client, session, &pair.public_label).await?;
        let found_private =
            find_objects_by_label(&mut client, session, &pair.private_label).await?;
        let found_by_id = find_objects_by_id(&mut client, session, &pair.key_id).await?;
        assert_eq!(found_public.len(), 1);
        assert_eq!(found_private.len(), 1);
        assert_eq!(found_by_id.len(), 2);

        let reopened_decrypted = rsa_encrypt_and_decrypt(
            &mut client,
            session,
            found_public[0],
            found_private[0],
            payload.as_bytes(),
        )
        .await?;
        assert_eq!(reopened_decrypted, payload.as_bytes());

        client.destroy_object(session, found_public[0]).await.map_err(|rv| rv.to_string())?;
        client.destroy_object(session, found_private[0]).await.map_err(|rv| rv.to_string())?;
        client.logout(session).await.map_err(|rv| rv.to_string())?;
        client.close_session(session).await.map_err(|rv| rv.to_string())?;
        client.finalize().await.map_err(|rv| rv.to_string())?;
        daemon.shutdown().await?;
        return Ok(());
    }

    client.logout(session).await.map_err(|rv| rv.to_string())?;
    client.close_session(session).await.map_err(|rv| rv.to_string())?;
    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}

async fn run_provider_capability_matrix(fixture: ProviderFixture) -> Result<(), String> {
    let daemon = DaemonHarness::start(&fixture).await?;
    let mut client = initialized_client(daemon.endpoint()).await?;

    let slot = ensure_user_token(&mut client, &fixture).await?;
    let mechanisms = client.get_mechanism_list(slot).await.map_err(|rv| rv.to_string())?;
    if mechanisms.is_empty() {
        return Err(format!("{} reported an empty mechanism list", fixture.name));
    }

    let provider = fixture.name;
    for probe in CAPABILITY_PROBES {
        let advertised = mechanisms.contains(&probe.mechanism);
        match client.get_mechanism_info(slot, probe.mechanism).await {
            Ok(info) => {
                if !advertised {
                    return Err(format!(
                        "{provider}: C_GetMechanismInfo succeeded for unadvertised {}",
                        probe.name
                    ));
                }
                eprintln!(
                    "{provider}: {} advertised flags=0x{:08X} min={} max={}",
                    probe.name, info.flags.0, info.min_key_size, info.max_key_size
                );
            }
            Err(rv) if advertised => {
                return Err(format!(
                    "{provider}: advertised {} but C_GetMechanismInfo returned {rv}",
                    probe.name
                ));
            }
            Err(CkRv::MECHANISM_INVALID) => {
                eprintln!("{provider}: {} not advertised", probe.name);
            }
            Err(rv) => {
                return Err(format!(
                    "{provider}: unadvertised {} returned {rv}, expected CKR_MECHANISM_INVALID",
                    probe.name
                ));
            }
        }
    }

    let unsupported = first_unadvertised_probe(&mechanisms)?;
    expect_mechanism_invalid(
        provider,
        "C_GetMechanismInfo",
        unsupported,
        client.get_mechanism_info(slot, unsupported.mechanism).await,
    )?;

    let session = open_public_session(&mut client, slot, true).await?;
    let mechanism = CkMechanism { mechanism_type: unsupported.mechanism, params: None };
    expect_mechanism_invalid(
        provider,
        "C_DigestInit",
        unsupported,
        client.digest_init(session, &mechanism).await,
    )?;

    client.close_session(session).await.map_err(|rv| rv.to_string())?;
    client.finalize().await.map_err(|rv| rv.to_string())?;
    daemon.shutdown().await?;
    Ok(())
}

#[tokio::test]
#[ignore] // optional: auto-detects system NSS softokn or uses PKCS11_PROXY_NSS_*
async fn nss_softokn_smoke_suite() -> Result<(), String> {
    let Some(fixture) = optional_nss_fixture().await? else {
        return Ok(());
    };
    run_optional_backend_smoke(fixture).await
}

#[tokio::test]
#[ignore] // optional: requires PKCS11_PROXY_KRYOPTIC_MODULE
async fn kryoptic_smoke_suite() -> Result<(), String> {
    let Some(fixture) = optional_kryoptic_fixture().await? else {
        return Ok(());
    };
    run_optional_backend_smoke(fixture).await
}

#[tokio::test]
#[ignore] // optional: auto-detects system NSS softokn or uses PKCS11_PROXY_NSS_*
async fn nss_provider_capability_matrix() -> Result<(), String> {
    let Some(fixture) = optional_nss_fixture().await? else {
        return Ok(());
    };
    run_provider_capability_matrix(fixture).await
}

#[tokio::test]
#[ignore] // optional: requires PKCS11_PROXY_KRYOPTIC_MODULE
async fn kryoptic_provider_capability_matrix() -> Result<(), String> {
    let Some(fixture) = optional_kryoptic_fixture().await? else {
        return Ok(());
    };
    run_provider_capability_matrix(fixture).await
}
