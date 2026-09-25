//! Secret CLI inputs (W1-C11-15, W1-L2-11).
//!
//! Secret hex args (`--input`, `--wrapped-key`, `--value`, Verify's
//! `--data`/`--signature`) and PINs must be loadable without argv (which
//! leaks via `ps` and shell history): every secret accepts an env-var
//! fallback, secret hex args additionally accept `--<flag>-file` and
//! `--<flag>-stdin`, and `--pin` accepts `--pin-stdin`. An explicit argv
//! value still works but prints a stderr warning naming the safer
//! alternatives.

use std::path::PathBuf;

use pkcs11_proxy_ng_types::SecretBytes;

/// One secret hex argument: its argv flag stem plus its env fallback.
pub(crate) struct SecretSpec<'a> {
    /// Flag stem: `--input` + `--input-file` + `--input-stdin`.
    pub flag: &'a str,
    /// Env var clap reads into the inline value.
    pub env_var: &'a str,
}

pub(crate) const INPUT_SPEC: SecretSpec<'static> =
    SecretSpec { flag: "input", env_var: "PKCS11_PROXY_INPUT" };
pub(crate) const WRAPPED_KEY_SPEC: SecretSpec<'static> =
    SecretSpec { flag: "wrapped-key", env_var: "PKCS11_PROXY_WRAPPED_KEY" };
pub(crate) const VALUE_SPEC: SecretSpec<'static> =
    SecretSpec { flag: "value", env_var: "PKCS11_PROXY_VALUE" };
pub(crate) const DATA_SPEC: SecretSpec<'static> =
    SecretSpec { flag: "data", env_var: "PKCS11_PROXY_DATA" };
pub(crate) const SIGNATURE_SPEC: SecretSpec<'static> =
    SecretSpec { flag: "signature", env_var: "PKCS11_PROXY_SIGNATURE" };

/// The three sources one secret hex arg can come from.
pub(crate) struct SecretSources {
    /// `--<flag>` value (argv or env — argv detection needs `argv`).
    pub inline: Option<String>,
    /// `--<flag>-file` path (argv only, no env binding).
    pub file: Option<PathBuf>,
    /// `--<flag>-stdin` (argv only, no env binding).
    pub stdin: bool,
}

/// True when `argv` explicitly passes `--long`, either as `--long value`
/// or `--long=value`. Never matches a longer sibling (`--input` does not
/// match `--input-file`).
pub(crate) fn argv_uses_long_flag(argv: &[String], long: &str) -> bool {
    let bare = format!("--{long}");
    let joined = format!("--{long}=");
    argv.iter().any(|arg| arg == &bare || arg.starts_with(&joined))
}

/// Read the whole stdin stream as a secret string (production reader).
pub(crate) fn read_stdin_string() -> Result<String, Box<dyn core::error::Error>> {
    use std::io::Read as _;
    let mut body = String::new();
    std::io::stdin()
        .read_to_string(&mut body)
        .map_err(|e| format!("cannot read secret from stdin: {e}"))?;
    Ok(body)
}

/// Warning printed when a secret travels on argv.
pub(crate) fn argv_secret_warning(flag: &str, alternatives: &str) -> String {
    format!(
        "warning: --{flag} exposes a secret on the command line \
         (visible to other users via ps and shell history); prefer {alternatives}"
    )
}

/// Normalize a file/stdin secret body: strip one UTF-8 BOM, trim
/// surrounding whitespace (trailing newlines from `echo`), and reject
/// empty bodies loudly instead of sending an empty secret.
fn normalize_external_secret(
    body: String,
    what: &str,
) -> Result<String, Box<dyn core::error::Error>> {
    let body = body.strip_prefix('\u{FEFF}').unwrap_or(&body).trim();
    if body.is_empty() {
        return Err(format!("{what} provided an empty secret").into());
    }
    Ok(body.to_string())
}

fn read_secret_file(
    path: &std::path::Path,
    what: &str,
) -> Result<String, Box<dyn core::error::Error>> {
    let body = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {what} '{}': {e}", path.display()))?;
    normalize_external_secret(body, what)
}

/// Resolve one secret hex arg. At most one argv-explicit source wins
/// (`--<flag>` beats nothing: file > stdin > inline, with an error when
/// two argv sources collide); an env-filled inline value is the silent
/// fallback. File/stdin bodies are trimmed; empty bodies error.
pub(crate) fn resolve_optional_secret(
    spec: &SecretSpec,
    sources: SecretSources,
    argv: &[String],
    read_stdin: impl FnOnce() -> Result<String, Box<dyn core::error::Error>>,
    warn: impl FnOnce(String),
) -> Result<Option<String>, Box<dyn core::error::Error>> {
    let file_flag = format!("{}-file", spec.flag);
    let stdin_flag = format!("{}-stdin", spec.flag);
    let inline_argv = argv_uses_long_flag(argv, spec.flag);
    let explicit =
        [inline_argv, sources.file.is_some(), sources.stdin].into_iter().filter(|b| *b).count();
    if explicit > 1 {
        return Err(
            format!("pass only one of --{}, --{file_flag}, --{stdin_flag}", spec.flag).into()
        );
    }
    if let Some(path) = sources.file {
        return Ok(Some(read_secret_file(&path, &format!("--{file_flag}"))?));
    }
    if sources.stdin {
        return Ok(Some(normalize_external_secret(read_stdin()?, &format!("--{stdin_flag}"))?));
    }
    if let Some(inline) = sources.inline {
        if inline_argv {
            warn(argv_secret_warning(
                spec.flag,
                &format!(
                    "--{file_flag}, --{stdin_flag}, or the {} environment variable",
                    spec.env_var
                ),
            ));
        }
        return Ok(Some(inline));
    }
    Ok(None)
}

/// Resolve a required secret hex arg (missing value is a loud error
/// naming every accepted source).
pub(crate) fn resolve_required_secret(
    spec: &SecretSpec,
    sources: SecretSources,
    argv: &[String],
    read_stdin: impl FnOnce() -> Result<String, Box<dyn core::error::Error>>,
    warn: impl FnOnce(String),
) -> Result<String, Box<dyn core::error::Error>> {
    resolve_optional_secret(spec, sources, argv, read_stdin, warn)?.ok_or_else(|| {
        format!(
            "missing --{}: pass --{}, --{}-file, --{}-stdin, or set {}",
            spec.flag, spec.flag, spec.flag, spec.flag, spec.env_var
        )
        .into()
    })
}

/// Resolve `--pin` (argv, `PKCS11_PROXY_PIN` env, or `--pin-stdin`).
pub(crate) fn resolve_optional_pin(
    inline: Option<SecretBytes>,
    stdin: bool,
    argv: &[String],
    read_stdin: impl FnOnce() -> Result<String, Box<dyn core::error::Error>>,
    warn: impl FnOnce(String),
) -> Result<Option<SecretBytes>, Box<dyn core::error::Error>> {
    let inline_argv = argv_uses_long_flag(argv, "pin");
    if inline_argv && stdin {
        return Err("pass only one of --pin, --pin-stdin".into());
    }
    if stdin {
        return Ok(Some(SecretBytes::from(normalize_external_secret(
            read_stdin()?,
            "--pin-stdin",
        )?)));
    }
    if let Some(inline) = inline {
        if inline_argv {
            warn(argv_secret_warning(
                "pin",
                "--pin-stdin or the PKCS11_PROXY_PIN environment variable",
            ));
        }
        return Ok(Some(inline));
    }
    Ok(None)
}

/// Resolve a required `--pin` (missing value is a loud error naming
/// every accepted source).
pub(crate) fn resolve_required_pin(
    inline: Option<SecretBytes>,
    stdin: bool,
    argv: &[String],
    read_stdin: impl FnOnce() -> Result<String, Box<dyn core::error::Error>>,
    warn: impl FnOnce(String),
) -> Result<SecretBytes, Box<dyn core::error::Error>> {
    resolve_optional_pin(inline, stdin, argv, read_stdin, warn)?.ok_or_else(|| {
        "missing PIN: pass --pin, --pin-stdin, or set PKCS11_PROXY_PIN".to_string().into()
    })
}

/// Resolve an argv-or-env-only PIN (`--so-pin`, `--new-pin`): no stdin
/// variant, but the argv path still warns.
pub(crate) fn resolve_required_inline_pin(
    inline: Option<SecretBytes>,
    flag: &str,
    env_var: &str,
    argv: &[String],
    warn: impl FnOnce(String),
) -> Result<SecretBytes, Box<dyn core::error::Error>> {
    if let Some(inline) = inline {
        if argv_uses_long_flag(argv, flag) {
            warn(argv_secret_warning(flag, &format!("the {env_var} environment variable")));
        }
        return Ok(inline);
    }
    Err(format!("missing --{flag}: pass --{flag} or set {env_var}").into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    fn sources(inline: Option<&str>, file: Option<PathBuf>, stdin: bool) -> SecretSources {
        SecretSources { inline: inline.map(str::to_string), file, stdin }
    }

    fn fail_stdin() -> Result<String, Box<dyn core::error::Error>> {
        unreachable!("stdin must not be read on this path")
    }

    fn fail_warn(_: String) {
        panic!("no warning expected on this path")
    }

    // W1-C11-15: argv detection matches `--flag value` and `--flag=value`
    // but never a longer sibling such as `--input-file`.
    #[test]
    fn argv_flag_detection_ignores_longer_siblings() {
        assert!(argv_uses_long_flag(&argv(&["cli", "sign", "--input", "ab"]), "input"));
        assert!(argv_uses_long_flag(&argv(&["cli", "sign", "--input=ab"]), "input"));
        assert!(!argv_uses_long_flag(&argv(&["cli", "sign", "--input-file", "p"]), "input"));
        assert!(!argv_uses_long_flag(&argv(&["cli", "sign", "--input-stdin"]), "input"));
        assert!(!argv_uses_long_flag(&argv(&["cli", "sign"]), "input"));
        assert!(argv_uses_long_flag(&argv(&["cli", "--pin-stdin"]), "pin-stdin"));
    }

    // W1-C11-15: the warning names the leak and the alternatives.
    #[test]
    fn argv_warning_names_leak_and_alternatives() {
        let msg = argv_secret_warning("input", "--input-file");
        assert!(msg.contains("--input"), "must name flag: {msg}");
        assert!(msg.contains("--input-file"), "must name alternative: {msg}");
        assert!(msg.contains("ps") || msg.contains("history"), "must name leak: {msg}");
    }

    // W1-C11-15: argv inline resolves but warns; env inline (no argv
    // flag) resolves silently.
    #[test]
    fn inline_argv_warns_env_stays_silent() {
        let mut warned = Vec::new();
        let out = resolve_required_secret(
            &INPUT_SPEC,
            sources(Some("ab12"), None, false),
            &argv(&["cli", "sign", "--input", "ab12"]),
            fail_stdin,
            |m| warned.push(m),
        )
        .unwrap();
        assert_eq!(out, "ab12");
        assert_eq!(warned.len(), 1, "argv inline must warn");

        let out = resolve_required_secret(
            &INPUT_SPEC,
            sources(Some("ab12"), None, false),
            &argv(&["cli", "sign"]),
            fail_stdin,
            fail_warn,
        )
        .unwrap();
        assert_eq!(out, "ab12");
    }

    // W1-C11-15: file and stdin sources resolve (trimmed) without warnings.
    #[test]
    fn file_and_stdin_sources_resolve_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input.hex");
        std::fs::write(&path, "ab12\n").unwrap();
        let out = resolve_required_secret(
            &INPUT_SPEC,
            sources(None, Some(path), false),
            &argv(&["cli", "sign", "--input-file", "input.hex"]),
            fail_stdin,
            fail_warn,
        )
        .unwrap();
        assert_eq!(out, "ab12");

        let out = resolve_required_secret(
            &INPUT_SPEC,
            sources(None, None, true),
            &argv(&["cli", "sign", "--input-stdin"]),
            || Ok("cd34\r\n".to_string()),
            fail_warn,
        )
        .unwrap();
        assert_eq!(out, "cd34");
    }

    // W1-C11-15: two argv-explicit sources are a loud error, not silent
    // precedence; an env-filled inline stays a quiet fallback under an
    // explicit file/stdin choice.
    #[test]
    fn conflicting_argv_sources_error_env_fallback_yields() {
        for extra in [
            sources(Some("aa"), Some(PathBuf::from("f")), false),
            sources(Some("aa"), None, true),
            sources(None, Some(PathBuf::from("f")), true),
        ] {
            let err = resolve_required_secret(
                &INPUT_SPEC,
                extra,
                &argv(&["cli", "sign", "--input", "aa", "--input-file", "f", "--input-stdin"]),
                fail_stdin,
                fail_warn,
            )
            .unwrap_err()
            .to_string();
            assert!(err.contains("--input-file"), "must name spellings: {err}");
            assert!(err.contains("--input-stdin"), "must name spellings: {err}");
        }

        // Env-filled inline + explicit file: file wins, no conflict.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input.hex");
        std::fs::write(&path, "bb").unwrap();
        let out = resolve_required_secret(
            &INPUT_SPEC,
            sources(Some("aa"), Some(path), false),
            &argv(&["cli", "sign", "--input-file", "input.hex"]),
            fail_stdin,
            fail_warn,
        )
        .unwrap();
        assert_eq!(out, "bb");
    }

    // W1-C11-15: missing required secrets error naming every source;
    // missing optional secrets resolve to None.
    #[test]
    fn missing_required_errors_optional_yields_none() {
        let err = resolve_required_secret(
            &INPUT_SPEC,
            sources(None, None, false),
            &argv(&["cli", "sign"]),
            fail_stdin,
            fail_warn,
        )
        .unwrap_err()
        .to_string();
        for spelling in ["--input", "--input-file", "--input-stdin", "PKCS11_PROXY_INPUT"] {
            assert!(err.contains(spelling), "must name {spelling}: {err}");
        }
        let out = resolve_optional_secret(
            &VALUE_SPEC,
            sources(None, None, false),
            &argv(&["cli", "create-object"]),
            fail_stdin,
            fail_warn,
        )
        .unwrap();
        assert_eq!(out, None);
    }

    // W1-C11-15: empty file/stdin bodies are a loud error, never an
    // empty secret.
    #[test]
    fn empty_external_bodies_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.hex");
        std::fs::write(&path, "\n").unwrap();
        assert!(
            resolve_required_secret(
                &INPUT_SPEC,
                sources(None, Some(path), false),
                &argv(&["cli", "sign", "--input-file", "empty.hex"]),
                fail_stdin,
                fail_warn,
            )
            .is_err()
        );
        assert!(
            resolve_required_secret(
                &INPUT_SPEC,
                sources(None, None, true),
                &argv(&["cli", "sign", "--input-stdin"]),
                || Ok("  \n".to_string()),
                fail_warn,
            )
            .is_err()
        );
        assert!(
            resolve_optional_secret(
                &VALUE_SPEC,
                sources(None, None, true),
                &argv(&["cli", "create-object", "--value-stdin"]),
                || Ok(String::new()),
                fail_warn,
            )
            .is_err()
        );
    }

    // W1-L2-11: PINs resolve from argv (warned), env (silent), or stdin
    // (silent, wiping storage); argv+stdin collide loudly.
    #[test]
    fn pin_resolution_warns_on_argv_only() {
        let mut warned = Vec::new();
        let pin = resolve_required_pin(
            Some(SecretBytes::from("1234")),
            false,
            &argv(&["cli", "sign", "--pin", "1234"]),
            fail_stdin,
            |m| warned.push(m),
        )
        .unwrap();
        pin.expose(|b| assert_eq!(b, b"1234"));
        assert_eq!(warned.len(), 1, "argv PIN must warn");

        let pin = resolve_required_pin(
            Some(SecretBytes::from("1234")),
            false,
            &argv(&["cli", "sign"]),
            fail_stdin,
            fail_warn,
        )
        .unwrap();
        pin.expose(|b| assert_eq!(b, b"1234"));

        let pin = resolve_required_pin(
            None,
            true,
            &argv(&["cli", "sign", "--pin-stdin"]),
            || Ok("5678\n".to_string()),
            fail_warn,
        )
        .unwrap();
        pin.expose(|b| assert_eq!(b, b"5678"));

        let err = resolve_required_pin(
            Some(SecretBytes::from("1234")),
            true,
            &argv(&["cli", "sign", "--pin", "1234", "--pin-stdin"]),
            fail_stdin,
            fail_warn,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("--pin-stdin"), "must name spellings: {err}");

        let err = resolve_required_pin(None, false, &argv(&["cli", "sign"]), fail_stdin, fail_warn)
            .unwrap_err()
            .to_string();
        for spelling in ["--pin", "--pin-stdin", "PKCS11_PROXY_PIN"] {
            assert!(err.contains(spelling), "must name {spelling}: {err}");
        }
        assert!(
            resolve_optional_pin(
                None,
                false,
                &argv(&["cli", "find-objects"]),
                fail_stdin,
                fail_warn
            )
            .unwrap()
            .is_none()
        );
    }

    // W1-L2-11: argv-or-env-only PINs warn on the argv path and error
    // loudly when required-but-missing.
    #[test]
    fn inline_only_pin_warns_on_argv() {
        let mut warned = Vec::new();
        let pin = resolve_required_inline_pin(
            Some(SecretBytes::from("so")),
            "so-pin",
            "PKCS11_PROXY_SO_PIN",
            &argv(&["cli", "init-token", "--so-pin", "so"]),
            |m| warned.push(m),
        )
        .unwrap();
        pin.expose(|b| assert_eq!(b, b"so"));
        assert_eq!(warned.len(), 1, "argv SO PIN must warn");

        resolve_required_inline_pin(
            Some(SecretBytes::from("so")),
            "so-pin",
            "PKCS11_PROXY_SO_PIN",
            &argv(&["cli", "init-token"]),
            fail_warn,
        )
        .unwrap();

        let err = resolve_required_inline_pin(
            None,
            "new-pin",
            "PKCS11_PROXY_NEW_PIN",
            &argv(&["cli", "init-pin"]),
            fail_warn,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("PKCS11_PROXY_NEW_PIN"), "must name env: {err}");
    }
}
