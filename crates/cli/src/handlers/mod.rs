mod admin;
pub(crate) mod audit;
mod crypto;
mod objects;
mod query;

use pkcs11_proxy_ng_client::Pkcs11Client;
use pkcs11_proxy_ng_types::*;

use crate::cli::Commands;
use crate::pkcs11_names::object_class_name;

pub(crate) type CliResult = Result<(), Box<dyn core::error::Error>>;

/// Sentinel for `verify` reporting `CKR_SIGNATURE_INVALID` (W1-C11-12):
/// the handler releases its session and returns this instead of
/// `process::exit`-ing, so `main` can finalize and exit with a code
/// distinct from generic failures.
#[derive(Debug)]
pub(crate) struct VerifyInvalid;

impl core::fmt::Display for VerifyInvalid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "signature INVALID (CKR_SIGNATURE_INVALID)")
    }
}

impl core::error::Error for VerifyInvalid {}

/// Format a `CkRv` from a named PKCS#11 entry point as a CLI-facing error.
/// Use with `.map_err(cli_err("C_FooName"))?`. Centralises the
/// `"C_FooName failed: {rv}"` shape that was copy-pasted at 37+ sites
/// (W1-C11-16: symbolic CKR name via `CkRv` Display, hex alongside).
pub(crate) fn cli_err(fn_name: &'static str) -> impl FnOnce(CkRv) -> Box<dyn core::error::Error> {
    move |e| format!("{fn_name} failed: {e}").into()
}

/// Build a (possibly parameterized) mechanism from its CLI name plus an
/// optional JSON `--params-file` (W1-C11-09): the single shared helper
/// for the crypto/object handlers (formerly triplicated across
/// sign_verify.rs/digest_cipher.rs/key_ops.rs).
pub(crate) fn cli_mechanism(
    name: &str,
    params_file: Option<&std::path::Path>,
) -> Result<CkMechanism, Box<dyn core::error::Error>> {
    crate::mech_params::build_mechanism(name, params_file)
}

/// Require explicit confirmation for a destructive operation (W1-C11-27):
/// `--force` skips the prompt (scripting); otherwise the operator must
/// type `yes` (or `y`) on stdin. Anything else — including EOF, so
/// non-TTY stdin fails closed — aborts with an error naming `--force`.
/// The prompt goes to stderr so stdout stays plumbable.
pub(crate) fn confirm_destructive(
    prompt: &str,
    force: bool,
    reader: &mut dyn std::io::BufRead,
) -> Result<(), Box<dyn core::error::Error>> {
    if force {
        return Ok(());
    }
    eprint!("{prompt}");
    let mut answer = String::new();
    reader.read_line(&mut answer).map_err(|e| format!("cannot read confirmation: {e}"))?;
    if answer.trim().eq_ignore_ascii_case("yes") || answer.trim().eq_ignore_ascii_case("y") {
        return Ok(());
    }
    Err("aborted: confirmation required (type 'yes' or rerun with --force)".into())
}

/// Commands `main` dispatches before the PKCS#11 client is initialized
/// (W1-C11-20): they never reach `run_command`, so their arms below are
/// all explicit `unreachable!` with a reason — never silent `Ok(())`.
pub(crate) fn dispatched_before_client_init(command: &Commands) -> bool {
    matches!(
        command,
        Commands::ListMechanismNames | Commands::Health { .. } | Commands::Audit { .. }
    )
}

pub(crate) async fn run_command(client: &mut Pkcs11Client, command: Commands) -> CliResult {
    use crate::secrets as s;
    debug_assert!(
        !dispatched_before_client_init(&command),
        "main must dispatch this command before client init"
    );
    // Secret resolvers need the raw argv to tell an explicit `--flag`
    // value (warned) from an env-filled one (silent).
    let argv: Vec<String> =
        std::env::args_os().map(|arg| arg.to_string_lossy().into_owned()).collect();
    // Production secret IO: real stdin, warnings on stderr.
    let stdin = s::read_stdin_string;
    let warn = |message: String| eprintln!("{message}");
    let input_sources =
        |inline: Option<String>, file: Option<std::path::PathBuf>, stdin_flag: bool| {
            s::SecretSources { inline, file, stdin: stdin_flag }
        };
    match command {
        Commands::ListSlots { token_present } => query::list_slots(client, token_present).await,
        Commands::SlotInfo { slot_id } => query::slot_info(client, slot_id).await,
        Commands::TokenInfo { slot_id } => query::token_info(client, slot_id).await,
        Commands::ListMechanisms { slot_id } => query::list_mechanisms(client, slot_id).await,
        Commands::GetInfo => query::get_info(client).await,
        Commands::SessionInfo { slot_id, pin, pin_stdin } => {
            let pin = s::resolve_optional_pin(pin, pin_stdin, &argv, stdin, warn)?;
            query::session_info(client, slot_id, pin).await
        }
        Commands::Random { slot_id, len, format } => {
            query::random(client, slot_id, len, format).await
        }
        // All three are dispatched in main() before the PKCS#11 client
        // is initialized, so these arms are never reached (W1-C11-20).
        Commands::ListMechanismNames => {
            unreachable!("list-mechanism-names is dispatched in main before client init")
        }
        Commands::Health { .. } => {
            unreachable!("health is dispatched in main before client init")
        }
        Commands::Audit { .. } => {
            unreachable!("audit subcommands are dispatched in main before client init")
        }
        Commands::FindObjects { slot_id, pin, pin_stdin, label, verbose } => {
            let pin = s::resolve_optional_pin(pin, pin_stdin, &argv, stdin, warn)?;
            objects::find_objects(client, slot_id, pin, label, verbose).await
        }
        Commands::DestroyObject { slot_id, pin, pin_stdin, object_handle, force } => {
            let pin = s::resolve_optional_pin(pin, pin_stdin, &argv, stdin, warn)?;
            confirm_destructive(
                &format!(
                    "Destroy object {object_handle} on slot {slot_id}? This cannot be undone. \
                     Type 'yes' to confirm (or rerun with --force): "
                ),
                force,
                &mut std::io::stdin().lock(),
            )?;
            objects::destroy_object(client, slot_id, pin, object_handle).await
        }
        Commands::GetObjectSize { slot_id, pin, pin_stdin, object_handle } => {
            let pin = s::resolve_optional_pin(pin, pin_stdin, &argv, stdin, warn)?;
            objects::get_object_size(client, slot_id, pin, object_handle).await
        }
        Commands::CreateObject {
            slot_id,
            pin,
            pin_stdin,
            label,
            value,
            value_file,
            value_stdin,
        } => {
            let pin = s::resolve_required_pin(pin, pin_stdin, &argv, stdin, warn)?;
            let value = s::resolve_optional_secret(
                &s::VALUE_SPEC,
                input_sources(value, value_file, value_stdin),
                &argv,
                stdin,
                warn,
            )?;
            objects::create_object(client, slot_id, pin, label, value).await
        }
        Commands::GetAttribute { slot_id, pin, pin_stdin, object_handle, attr, redact } => {
            let pin = s::resolve_optional_pin(pin, pin_stdin, &argv, stdin, warn)?;
            objects::get_attribute(client, slot_id, pin, object_handle, attr, redact).await
        }
        Commands::ImportCertificate { slot_id, pin, pin_stdin, label, file } => {
            let pin = s::resolve_required_pin(pin, pin_stdin, &argv, stdin, warn)?;
            objects::import_certificate(client, slot_id, pin, label, file).await
        }
        Commands::WrapKey {
            slot_id,
            pin,
            pin_stdin,
            mechanism,
            params_file,
            wrapping_key_handle,
            key_handle,
        } => {
            let pin = s::resolve_required_pin(pin, pin_stdin, &argv, stdin, warn)?;
            objects::wrap_key(
                client,
                slot_id,
                pin,
                mechanism,
                params_file,
                wrapping_key_handle,
                key_handle,
            )
            .await
        }
        Commands::UnwrapKey {
            slot_id,
            pin,
            pin_stdin,
            mechanism,
            params_file,
            unwrapping_key_handle,
            wrapped_key,
            wrapped_key_file,
            wrapped_key_stdin,
            label,
        } => {
            let pin = s::resolve_required_pin(pin, pin_stdin, &argv, stdin, warn)?;
            let wrapped_key = s::resolve_required_secret(
                &s::WRAPPED_KEY_SPEC,
                input_sources(wrapped_key, wrapped_key_file, wrapped_key_stdin),
                &argv,
                stdin,
                warn,
            )?;
            objects::unwrap_key(
                client,
                slot_id,
                pin,
                mechanism,
                params_file,
                unwrapping_key_handle,
                wrapped_key,
                label,
            )
            .await
        }
        Commands::DeriveKey {
            slot_id,
            pin,
            pin_stdin,
            mechanism,
            params_file,
            base_key_handle,
            label,
        } => {
            let pin = s::resolve_required_pin(pin, pin_stdin, &argv, stdin, warn)?;
            objects::derive_key(
                client,
                slot_id,
                pin,
                mechanism,
                params_file,
                base_key_handle,
                label,
            )
            .await
        }
        Commands::GenerateKey {
            slot_id,
            pin,
            pin_stdin,
            mechanism,
            params_file,
            label,
            key_size,
        } => {
            let pin = s::resolve_required_pin(pin, pin_stdin, &argv, stdin, warn)?;
            objects::generate_key(client, slot_id, pin, mechanism, params_file, label, key_size)
                .await
        }
        Commands::GenerateKeyPair {
            slot_id,
            pin,
            pin_stdin,
            mechanism,
            params_file,
            label,
            key_size,
            ec_params,
        } => {
            let pin = s::resolve_required_pin(pin, pin_stdin, &argv, stdin, warn)?;
            objects::generate_key_pair(
                client,
                slot_id,
                pin,
                mechanism,
                params_file,
                label,
                key_size,
                ec_params,
            )
            .await
        }
        Commands::Sign {
            slot_id,
            pin,
            pin_stdin,
            key_label,
            mechanism,
            params_file,
            input,
            input_file,
            input_stdin,
        } => {
            let pin = s::resolve_required_pin(pin, pin_stdin, &argv, stdin, warn)?;
            let input = s::resolve_required_secret(
                &s::INPUT_SPEC,
                input_sources(input, input_file, input_stdin),
                &argv,
                stdin,
                warn,
            )?;
            crypto::sign(client, slot_id, pin, key_label, mechanism, params_file, input).await
        }
        Commands::Digest { slot_id, mechanism, params_file, input, input_file, input_stdin } => {
            let input = s::resolve_required_secret(
                &s::INPUT_SPEC,
                input_sources(input, input_file, input_stdin),
                &argv,
                stdin,
                warn,
            )?;
            crypto::digest(client, slot_id, mechanism, params_file, input).await
        }
        Commands::Encrypt {
            slot_id,
            pin,
            pin_stdin,
            key_label,
            mechanism,
            params_file,
            input,
            input_file,
            input_stdin,
        } => {
            let pin = s::resolve_required_pin(pin, pin_stdin, &argv, stdin, warn)?;
            let input = s::resolve_required_secret(
                &s::INPUT_SPEC,
                input_sources(input, input_file, input_stdin),
                &argv,
                stdin,
                warn,
            )?;
            crypto::encrypt(client, slot_id, pin, key_label, mechanism, params_file, input).await
        }
        Commands::Decrypt {
            slot_id,
            pin,
            pin_stdin,
            key_label,
            mechanism,
            params_file,
            input,
            input_file,
            input_stdin,
            redact,
        } => {
            let pin = s::resolve_required_pin(pin, pin_stdin, &argv, stdin, warn)?;
            let input = s::resolve_required_secret(
                &s::INPUT_SPEC,
                input_sources(input, input_file, input_stdin),
                &argv,
                stdin,
                warn,
            )?;
            crypto::decrypt(client, slot_id, pin, key_label, mechanism, params_file, input, redact)
                .await
        }
        Commands::Verify {
            slot_id,
            pin,
            pin_stdin,
            key_label,
            mechanism,
            params_file,
            data,
            data_file,
            data_stdin,
            signature,
            signature_file,
            signature_stdin,
        } => {
            let pin = s::resolve_optional_pin(pin, pin_stdin, &argv, stdin, warn)?;
            let data = s::resolve_required_secret(
                &s::DATA_SPEC,
                input_sources(data, data_file, data_stdin),
                &argv,
                stdin,
                warn,
            )?;
            let signature = s::resolve_required_secret(
                &s::SIGNATURE_SPEC,
                input_sources(signature, signature_file, signature_stdin),
                &argv,
                stdin,
                warn,
            )?;
            crypto::verify(client, slot_id, pin, key_label, mechanism, params_file, data, signature)
                .await
        }
        Commands::InitToken { slot_id, so_pin, label, force } => {
            let so_pin = s::resolve_required_inline_pin(
                Some(so_pin),
                "so-pin",
                "PKCS11_PROXY_SO_PIN",
                &argv,
                warn,
            )?;
            confirm_destructive(
                &format!(
                    "Initialize the token in slot {slot_id} with label '{label}'? This ERASES \
                     the token contents. Type 'yes' to confirm (or rerun with --force): "
                ),
                force,
                &mut std::io::stdin().lock(),
            )?;
            admin::init_token(client, slot_id, so_pin, label).await
        }
        Commands::InitPin { slot_id, so_pin, new_pin } => {
            let so_pin = s::resolve_required_inline_pin(
                Some(so_pin),
                "so-pin",
                "PKCS11_PROXY_SO_PIN",
                &argv,
                warn,
            )?;
            let new_pin = s::resolve_required_inline_pin(
                Some(new_pin),
                "new-pin",
                "PKCS11_PROXY_NEW_PIN",
                &argv,
                warn,
            )?;
            admin::init_pin(client, slot_id, so_pin, new_pin).await
        }
        Commands::SeedRandom { slot_id, pin, pin_stdin, seed } => {
            // W1-C11-33: optional PIN like digest/session-info/verify.
            let pin = s::resolve_optional_pin(pin, pin_stdin, &argv, stdin, warn)?;
            admin::seed_random(client, slot_id, pin, seed).await
        }
        Commands::SetPin { slot_id, pin, pin_stdin, new_pin } => {
            let pin = s::resolve_required_pin(pin, pin_stdin, &argv, stdin, warn)?;
            let new_pin = s::resolve_required_inline_pin(
                Some(new_pin),
                "new-pin",
                "PKCS11_PROXY_NEW_PIN",
                &argv,
                warn,
            )?;
            admin::set_pin(client, slot_id, pin, new_pin).await
        }
    }
}

pub(crate) async fn open_session(
    client: &mut Pkcs11Client,
    slot_id: u64,
    flags: CkSessionFlags,
) -> Result<CkSessionHandle, Box<dyn core::error::Error>> {
    client.open_session(CkSlotId(slot_id), flags).await.map_err(cli_err("C_OpenSession"))
}

pub(crate) async fn login_user(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    pin: SecretBytes,
) -> Result<(), Box<dyn core::error::Error>> {
    // By-value PIN (W1-L2-11): the wiping allocation transfers in and is
    // wiped on drop after login — no plain-String copy exists past parsing.
    let owned = pin.into_zeroizing();
    client
        .login(session, CkUserType::User, Some(owned.as_slice()))
        .await
        .map_err(cli_err("C_Login"))
}

pub(crate) async fn login_if_present(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    pin: Option<SecretBytes>,
) -> Result<(), Box<dyn core::error::Error>> {
    if let Some(pin) = pin {
        login_user(client, session, pin).await?;
    }
    Ok(())
}

pub(crate) async fn close_session(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    logged_in: bool,
) {
    if logged_in {
        let _ = client.logout(session).await;
    }
    let _ = client.close_session(session).await;
}

/// Page size for `find_objects` listing loops (W1-C11-13).
pub(crate) const FIND_PAGE_SIZE: u32 = 100;

/// Fetch every handle of an active find operation (W1-C11-13): loop
/// `find_objects` to exhaustion (a short/empty batch ends the search)
/// instead of capping the listing at one page.
pub(crate) async fn find_all_paged(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
) -> Result<Vec<CkObjectHandle>, Box<dyn core::error::Error>> {
    let mut objects = Vec::new();
    loop {
        let batch =
            client.find_objects(session, FIND_PAGE_SIZE).await.map_err(cli_err("C_FindObjects"))?;
        let exhausted = batch.len() < FIND_PAGE_SIZE as usize;
        objects.extend(batch);
        if exhausted {
            break;
        }
    }
    Ok(objects)
}

pub(crate) async fn find_key_by_label(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    key_label: &str,
    class: CkObjectClass,
) -> Result<CkObjectHandle, Box<dyn core::error::Error>> {
    // W1-C11-04: symmetric crypto (AES encrypt/decrypt, HMAC sign/verify)
    // operates on SECRET_KEY objects, but each op historically searched only
    // its asymmetric class. Try the requested class first so existing
    // behavior is unchanged, then fall back to SECRET_KEY.
    let mut classes = vec![class];
    if class != CkObjectClass::SECRET_KEY {
        classes.push(CkObjectClass::SECRET_KEY);
    }
    for class in classes {
        if let Some(handle) =
            find_unique_by_label_and_class(client, session, key_label, class).await?
        {
            return Ok(handle);
        }
    }

    Err(format!("No {} found with label '{key_label}'", object_class_name(class.0)).into())
}

/// Resolve one key by label+class (W1-C11-14): `CKA_LABEL` is not
/// unique, so fetch every match and error loudly on ambiguity (listing
/// the handles) instead of taking whatever comes first.
async fn find_unique_by_label_and_class(
    client: &mut Pkcs11Client,
    session: CkSessionHandle,
    key_label: &str,
    class: CkObjectClass,
) -> Result<Option<CkObjectHandle>, Box<dyn core::error::Error>> {
    let template = vec![
        CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(key_label.to_string().into())),
        },
        CkAttribute {
            attr_type: CkAttributeType::CLASS,
            value: Some(CkAttributeValue::Ulong(class.0)),
        },
    ];
    client
        .find_objects_init(session, Some(&template))
        .await
        .map_err(crate::handlers::cli_err("C_FindObjectsInit"))?;
    let objects = find_all_paged(client, session).await?;
    client
        .find_objects_final(session)
        .await
        .map_err(crate::handlers::cli_err("C_FindObjectsFinal"))?;

    match objects.len() {
        0 => Ok(None),
        1 => Ok(objects.into_iter().next()),
        _ => {
            let handles = objects.iter().map(|h| h.0.to_string()).collect::<Vec<_>>().join(", ");
            Err(format!(
                "Multiple {} objects found with label '{key_label}' (handles: {handles}); \
                 CKA_LABEL is not unique — delete or relabel duplicates, or select by handle",
                object_class_name(class.0)
            )
            .into())
        }
    }
}

#[cfg(test)]
mod tests {
    // W1-C11-09: exactly one `cli_mechanism` definition, shared by all
    // three former copy sites (source scan; behavior pinned below).
    #[test]
    fn cli_mechanism_defined_once_and_used_by_all_three_files() {
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let call_sites = [
            "src/handlers/crypto/sign_verify.rs",
            "src/handlers/crypto/digest_cipher.rs",
            "src/handlers/objects/key_ops.rs",
        ];
        // Assembled at runtime so this scan does not match its own needle.
        let needle = ["fn ", "cli_mechanism("].concat();
        let mut defs = Vec::new();
        for file in ["src/handlers/mod.rs"].into_iter().chain(call_sites) {
            let src = std::fs::read_to_string(manifest.join(file)).unwrap();
            let mut refs = 0;
            for (idx, line) in src.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                if code.contains(needle.as_str()) {
                    defs.push(format!("{file}:{}", idx + 1));
                }
                refs += code.matches("cli_mechanism").count();
            }
            if call_sites.contains(&file) {
                assert!(refs >= 2, "{file} must delegate to cli_mechanism (refs: {refs})");
            }
        }
        assert_eq!(defs.len(), 1, "expected one cli_mechanism definition, found: {defs:?}");
    }

    // W1-C11-16: cli_err prints the symbolic CKR name via CkRv
    // Display (hex alongside) instead of bare hex.
    #[test]
    fn cli_err_prints_symbolic_name_with_hex() {
        use super::cli_err;
        use pkcs11_proxy_ng_types::CkRv;
        let err = cli_err("C_Login")(CkRv::PIN_INCORRECT);
        let msg = err.to_string();
        assert!(msg.contains("C_Login"), "must name the entry point: {msg}");
        assert!(msg.contains("CKR_PIN_INCORRECT"), "must print symbolic name: {msg}");
        assert!(msg.contains("0x"), "must keep hex alongside: {msg}");
        // Unknown/vendor values still render (no panic, hex present).
        let err = cli_err("C_Foo")(CkRv(0xDEAD_BEEF));
        let msg = err.to_string();
        assert!(msg.contains("C_Foo"), "must name the entry point: {msg}");
        assert!(msg.contains("0x"), "unknown rv must keep hex: {msg}");
    }

    // W1-C11-09: the shared helper delegates to the params builder —
    // parameterless mechanisms pass through, parameterized ones demand
    // --params-file.
    #[test]
    fn shared_cli_mechanism_builds_both_families() {
        use super::cli_mechanism;
        use pkcs11_proxy_ng_types::CkMechanismType;
        let mech = cli_mechanism("AES_ECB", None).unwrap();
        assert_eq!(mech.mechanism_type, CkMechanismType::AES_ECB);
        assert_eq!(mech.params, None);
        let err = cli_mechanism("AES_GCM", None).unwrap_err().to_string();
        assert!(err.contains("--params-file"), "must hint: {err}");
    }

    // W1-C11-20: exactly the main-dispatched commands bypass run_command
    // (all three arms are unreachable-with-reason, not silent-Ok).
    #[test]
    fn main_dispatched_commands_pin() {
        use super::dispatched_before_client_init;
        use crate::cli::{AuditCmd, Commands};
        assert!(dispatched_before_client_init(&Commands::ListMechanismNames));
        assert!(dispatched_before_client_init(&Commands::Health { service: String::new() }));
        assert!(dispatched_before_client_init(&Commands::Audit {
            cmd: AuditCmd::Verify { dir: std::path::PathBuf::from("d"), public_key_hex: None },
        }));
        assert!(!dispatched_before_client_init(&Commands::GetInfo));
        assert!(!dispatched_before_client_init(&Commands::SlotInfo { slot_id: 1 }));
    }

    // W1-C11-27: --force skips the prompt without reading stdin.
    #[test]
    fn confirm_destructive_force_skips_prompt() {
        use super::confirm_destructive;
        let mut input = std::io::Cursor::new(b"no".as_slice());
        confirm_destructive("prompt", true, &mut input).unwrap();
        assert_eq!(input.position(), 0, "--force must not read stdin");
    }

    // W1-C11-27: without --force, only an explicit yes/no-yes confirms;
    // anything else (including EOF, for non-TTY stdin) aborts fail-closed
    // and names the --force bypass.
    #[test]
    fn confirm_destructive_reads_yes_no() {
        use super::confirm_destructive;
        for yes in ["yes", "YES", " y ", "Y\n"] {
            let mut input = std::io::Cursor::new(yes.as_bytes());
            confirm_destructive("prompt", false, &mut input)
                .unwrap_or_else(|e| panic!("{yes:?} must confirm: {e}"));
        }
        for no in ["no", "n", "", "abort", "yes please"] {
            let mut input = std::io::Cursor::new(no.as_bytes());
            let err = confirm_destructive("prompt", false, &mut input).unwrap_err().to_string();
            assert!(err.contains("--force"), "must name the bypass: {err}");
        }
        let mut eof = std::io::Cursor::new(b"".as_slice());
        assert!(confirm_destructive("prompt", false, &mut eof).is_err(), "EOF must abort");
    }
}
