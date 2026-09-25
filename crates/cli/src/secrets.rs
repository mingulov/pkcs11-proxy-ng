//! Secret CLI inputs (W1-C11-15, W1-L2-11; T14 wiping migration).
//!
//! Secret hex args (`--input`, `--wrapped-key`, `--value`, Verify's
//! `--data`/`--signature`) and PINs must be loadable without argv (which
//! leaks via `ps` and shell history): every secret accepts an env-var
//! fallback, secret hex args additionally accept `--<flag>-file` and
//! `--<flag>-stdin`, and `--pin` accepts `--pin-stdin`. An explicit argv
//! value still works but prints a stderr warning naming the safer
//! alternatives.
//!
//! T14 ownership: hex text travels in `Zeroizing<String>` (adopted, never
//! copied: clap's inline allocation is wrapped on arrival, file/stdin
//! bodies are read straight into wiping storage, normalization drains in
//! place, and hex decodes into a pre-sized wiping vector). PINs resolve to
//! `SecretBytes` as before. Explicit-argv detection comes from clap's own
//! value-source metadata ([`SecretOrigins`]), not from a retained argv copy.

use std::path::PathBuf;

use pkcs11_proxy_ng_types::SecretBytes;
use zeroize::Zeroizing;

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
    /// `--<flag>` value (argv or env — argv detection needs [`SecretOrigins`]).
    /// Wrapped on arrival: clap's allocation is adopted, never copied.
    pub inline: Option<Zeroizing<String>>,
    /// `--<flag>-file` path (argv only, no env binding).
    pub file: Option<PathBuf>,
    /// `--<flag>-stdin` (argv only, no env binding).
    pub stdin: bool,
}

/// Which inline secret flags were passed explicitly on argv (T14).
///
/// Captured once from clap's `ArgMatches` (`ValueSource::CommandLine`) so
/// resolvers can tell an explicit `--flag` value (warned) from an
/// env-filled one (silent) without retaining the raw argv — the old
/// `Vec<String>` copy held every secret value in plain memory.
///
/// Residuals (documented, not fixed here): clap keeps the parsed values
/// (plain `String`s, released at exit, never wiped); the OS keeps the
/// original argv/environ pages of this process (and the operator's shell
/// history file keeps whatever was typed). This metadata records flag
/// presence only — never values — and we never overwrite external argv
/// memory: it is borrowed process state, not ours to mutate.
#[derive(Debug, Default)]
pub(crate) struct SecretOrigins {
    pub input: bool,
    pub wrapped_key: bool,
    pub value: bool,
    pub data: bool,
    pub signature: bool,
    pub pin: bool,
    pub so_pin: bool,
    pub new_pin: bool,
}

impl SecretOrigins {
    /// Capture from the active subcommand's matches (`None` when no
    /// subcommand matched). Flag ids are clap derive field names; ids
    /// absent from this subcommand read as not-on-argv (`value_source`
    /// and `contains_id` both panic on undeclared ids, so membership is
    /// established through the `ids()` iterator first).
    pub fn from_subcommand_matches(matches: Option<&clap::ArgMatches>) -> Self {
        let known: std::collections::HashSet<&str> =
            matches.map(|m| m.ids().map(|id| id.as_str()).collect()).unwrap_or_default();
        let on_argv = |id: &str| {
            known.contains(id)
                && matches
                    .and_then(|m| m.value_source(id))
                    .is_some_and(|s| s == clap::parser::ValueSource::CommandLine)
        };
        Self {
            input: on_argv("input"),
            wrapped_key: on_argv("wrapped_key"),
            value: on_argv("value"),
            data: on_argv("data"),
            signature: on_argv("signature"),
            pin: on_argv("pin"),
            so_pin: on_argv("so_pin"),
            new_pin: on_argv("new_pin"),
        }
    }

    /// Explicit-argv bit for a secret-hex spec.
    pub fn for_spec(&self, spec: &SecretSpec) -> bool {
        match spec.flag {
            "input" => self.input,
            "wrapped-key" => self.wrapped_key,
            "value" => self.value,
            "data" => self.data,
            "signature" => self.signature,
            unknown => unreachable!("no origins bit for secret flag --{unknown}"),
        }
    }
}

/// Read a whole stream into wiping storage (T14). Buffer-growth
/// reallocations are transient allocator copies, never retained; a
/// mid-read I/O error drops the partial body with the wiping owner.
/// The error names the source, never the bytes.
fn read_external_string(
    reader: &mut dyn std::io::Read,
    what: &str,
) -> Result<Zeroizing<String>, Box<dyn core::error::Error>> {
    let mut body = Zeroizing::new(String::new());
    reader.read_to_string(&mut body).map_err(|e| format!("cannot read {what}: {e}"))?;
    Ok(body)
}

/// Read the whole stdin stream as a secret string (production reader).
pub(crate) fn read_stdin_string() -> Result<Zeroizing<String>, Box<dyn core::error::Error>> {
    read_external_string(&mut std::io::stdin(), "secret from stdin")
}

/// Warning printed when a secret travels on argv.
pub(crate) fn argv_secret_warning(flag: &str, alternatives: &str) -> String {
    format!(
        "warning: --{flag} exposes a secret on the command line \
         (visible to other users via ps and shell history); prefer {alternatives}"
    )
}

/// Normalize a file/stdin secret body in place (T14): strip one UTF-8
/// BOM, trim surrounding whitespace (trailing newlines from `echo`), and
/// reject empty bodies loudly instead of sending an empty secret. The
/// surviving range is computed from a borrow, then the outside ranges are
/// drained inside the same wiping allocation — no second copy.
fn normalize_external_secret(
    body: &mut Zeroizing<String>,
    what: &str,
) -> Result<(), Box<dyn core::error::Error>> {
    let (start, end) = {
        let text: &str = body;
        let trimmed = text.strip_prefix('\u{FEFF}').unwrap_or(text).trim();
        let start = trimmed.as_ptr() as usize - text.as_ptr() as usize;
        (start, start + trimmed.len())
    };
    body.drain(end..);
    body.drain(..start);
    if body.is_empty() {
        return Err(format!("{what} provided an empty secret").into());
    }
    Ok(())
}

fn read_secret_file(
    path: &std::path::Path,
    what: &str,
) -> Result<Zeroizing<String>, Box<dyn core::error::Error>> {
    let located = format!("{what} '{}'", path.display());
    let mut file = std::fs::File::open(path).map_err(|e| format!("cannot read {located}: {e}"))?;
    let mut body = read_external_string(&mut file, &located)?;
    normalize_external_secret(&mut body, what)?;
    Ok(body)
}

/// Decode hex text into a wiping owner (T14). Even length is validated
/// before sizing; the destination is pre-sized and wiped on drop, so a
/// mid-decode error (an invalid digit after a valid prefix) leaves
/// nothing plain. Error text never echoes the input.
pub(crate) fn decode_hex_secret(
    encoded: &Zeroizing<String>,
    what: &str,
) -> Result<SecretBytes, Box<dyn core::error::Error>> {
    let text: &str = encoded;
    if !text.len().is_multiple_of(2) {
        return Err(format!("{what}: Odd number of digits").into());
    }
    let mut decoded = Zeroizing::new(vec![0u8; text.len() / 2]);
    hex::decode_to_slice(text.as_bytes(), decoded.as_mut_slice())
        .map_err(|e| format!("{what}: {e}"))?;
    Ok(SecretBytes::from(decoded))
}

/// Resolve one secret hex arg. At most one argv-explicit source wins
/// (`--<flag>` beats nothing: file > stdin > inline, with an error when
/// two argv sources collide); an env-filled inline value is the silent
/// fallback. File/stdin bodies are trimmed; empty bodies error.
pub(crate) fn resolve_optional_secret(
    spec: &SecretSpec,
    sources: SecretSources,
    inline_argv: bool,
    read_stdin: impl FnOnce() -> Result<Zeroizing<String>, Box<dyn core::error::Error>>,
    warn: impl FnOnce(String),
) -> Result<Option<Zeroizing<String>>, Box<dyn core::error::Error>> {
    let file_flag = format!("{}-file", spec.flag);
    let stdin_flag = format!("{}-stdin", spec.flag);
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
        let mut body = read_stdin()?;
        normalize_external_secret(&mut body, &format!("--{stdin_flag}"))?;
        return Ok(Some(body));
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
    inline_argv: bool,
    read_stdin: impl FnOnce() -> Result<Zeroizing<String>, Box<dyn core::error::Error>>,
    warn: impl FnOnce(String),
) -> Result<Zeroizing<String>, Box<dyn core::error::Error>> {
    resolve_optional_secret(spec, sources, inline_argv, read_stdin, warn)?.ok_or_else(|| {
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
    inline_argv: bool,
    read_stdin: impl FnOnce() -> Result<Zeroizing<String>, Box<dyn core::error::Error>>,
    warn: impl FnOnce(String),
) -> Result<Option<SecretBytes>, Box<dyn core::error::Error>> {
    if inline_argv && stdin {
        return Err("pass only one of --pin, --pin-stdin".into());
    }
    if stdin {
        let mut body = read_stdin()?;
        normalize_external_secret(&mut body, "--pin-stdin")?;
        // Ownership transfer, not a copy: the wiping wrapper keeps an
        // empty String (zeroize has no `into_inner`; `mem::take` moves
        // the live allocation out).
        return Ok(Some(SecretBytes::from(std::mem::take(&mut *body))));
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
    inline_argv: bool,
    read_stdin: impl FnOnce() -> Result<Zeroizing<String>, Box<dyn core::error::Error>>,
    warn: impl FnOnce(String),
) -> Result<SecretBytes, Box<dyn core::error::Error>> {
    resolve_optional_pin(inline, stdin, inline_argv, read_stdin, warn)?.ok_or_else(|| {
        "missing PIN: pass --pin, --pin-stdin, or set PKCS11_PROXY_PIN".to_string().into()
    })
}

/// Resolve an argv-or-env-only PIN (`--so-pin`, `--new-pin`): no stdin
/// variant, but the argv path still warns.
pub(crate) fn resolve_required_inline_pin(
    inline: Option<SecretBytes>,
    flag: &str,
    env_var: &str,
    inline_argv: bool,
    warn: impl FnOnce(String),
) -> Result<SecretBytes, Box<dyn core::error::Error>> {
    if let Some(inline) = inline {
        if inline_argv {
            warn(argv_secret_warning(flag, &format!("the {env_var} environment variable")));
        }
        return Ok(inline);
    }
    Err(format!("missing --{flag}: pass --{flag} or set {env_var}").into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wiping(text: &str) -> Zeroizing<String> {
        Zeroizing::new(text.to_string())
    }

    fn sources(inline: Option<&str>, file: Option<PathBuf>, stdin: bool) -> SecretSources {
        SecretSources { inline: inline.map(|s| Zeroizing::new(s.to_string())), file, stdin }
    }

    fn fail_stdin() -> Result<Zeroizing<String>, Box<dyn core::error::Error>> {
        unreachable!("stdin must not be read on this path")
    }

    fn fail_warn(_: String) {
        panic!("no warning expected on this path")
    }

    // T14: clap value-source metadata replaces the argv scan — `--flag
    // value` and `--flag=value` both read as explicit, a longer sibling
    // (`--input-file`) never lights the `--input` bit, and absent flags
    // read silent.
    #[test]
    fn origins_capture_explicit_argv_flags() {
        use clap::CommandFactory as _;

        fn origins_for(argv: &[&str]) -> SecretOrigins {
            let matches =
                crate::cli::Cli::command().try_get_matches_from(argv).expect("must parse");
            SecretOrigins::from_subcommand_matches(matches.subcommand().map(|(_, m)| m))
        }

        // `sign` declares `--input`/`--pin` (among others); ids it does
        // not declare read silent.
        let sign = origins_for(&[
            "pkcs11-proxy-ng-cli",
            "sign",
            "--slot-id",
            "1",
            "--pin",
            "1234",
            "--key-label",
            "k",
            "--mechanism",
            "SHA256_RSA_PKCS",
            "--input",
            "ab",
        ]);
        assert!(sign.input, "--input value form must read explicit");
        assert!(sign.pin, "--pin must read explicit");
        assert!(!sign.wrapped_key, "undeclared id must read silent");
        assert!(!sign.so_pin, "absent flag must read silent");

        let joined = origins_for(&[
            "pkcs11-proxy-ng-cli",
            "sign",
            "--slot-id",
            "1",
            "--key-label",
            "k",
            "--mechanism",
            "SHA256_RSA_PKCS",
            "--input=ab",
        ]);
        assert!(joined.input, "--input=value form must read explicit");
        assert!(!joined.pin, "env-or-absent pin must read silent");

        let sibling = origins_for(&[
            "pkcs11-proxy-ng-cli",
            "sign",
            "--slot-id",
            "1",
            "--key-label",
            "k",
            "--mechanism",
            "SHA256_RSA_PKCS",
            "--input-file",
            "p",
        ]);
        assert!(!sibling.input, "--input-file must not light the --input bit");

        let init = origins_for(&[
            "pkcs11-proxy-ng-cli",
            "init-pin",
            "--slot-id",
            "1",
            "--so-pin",
            "so",
            "--new-pin",
            "new",
        ]);
        assert!(init.so_pin && init.new_pin, "kebab longs map to field ids");
        assert!(!init.pin, "absent pin must read silent");

        // Every remaining secret id, proven against its own command (a
        // mistyped id would read silent forever).
        let unwrap = origins_for(&[
            "pkcs11-proxy-ng-cli",
            "unwrap-key",
            "--slot-id",
            "1",
            "--mechanism",
            "AES_KEY_WRAP",
            "--unwrapping-key-handle",
            "7",
            "--wrapped-key",
            "cd",
        ]);
        assert!(unwrap.wrapped_key, "--wrapped-key must light its bit");
        assert!(!unwrap.input, "other bits stay silent");

        let create = origins_for(&[
            "pkcs11-proxy-ng-cli",
            "create-object",
            "--slot-id",
            "1",
            "--label",
            "l",
            "--value",
            "ef",
        ]);
        assert!(create.value, "--value must light its bit");

        let verify = origins_for(&[
            "pkcs11-proxy-ng-cli",
            "verify",
            "--slot-id",
            "1",
            "--key-label",
            "k",
            "--mechanism",
            "SHA256_RSA_PKCS",
            "--data",
            "aa",
            "--signature",
            "bb",
        ]);
        assert!(verify.data && verify.signature, "--data/--signature must light their bits");

        let none = SecretOrigins::from_subcommand_matches(None);
        assert!(!none.for_spec(&INPUT_SPEC), "no subcommand reads silent");
        assert!(!SecretOrigins::default().for_spec(&DATA_SPEC), "default reads silent");
    }

    // T14: every spec maps to its own origins bit (a new spec without a
    // bit fails loudly in `for_spec`, not silently).
    #[test]
    fn origins_map_every_secret_spec() {
        let all_true = SecretOrigins {
            input: true,
            wrapped_key: true,
            value: true,
            data: true,
            signature: true,
            pin: true,
            so_pin: true,
            new_pin: true,
        };
        for spec in [&INPUT_SPEC, &WRAPPED_KEY_SPEC, &VALUE_SPEC, &DATA_SPEC, &SIGNATURE_SPEC] {
            assert!(all_true.for_spec(spec), "--{} must map to a bit", spec.flag);
            assert!(!SecretOrigins::default().for_spec(spec), "--{} defaults silent", spec.flag);
        }
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
            true,
            fail_stdin,
            |m| warned.push(m),
        )
        .unwrap();
        assert_eq!(out.as_str(), "ab12");
        assert_eq!(warned.len(), 1, "argv inline must warn");

        let out = resolve_required_secret(
            &INPUT_SPEC,
            sources(Some("ab12"), None, false),
            false,
            fail_stdin,
            fail_warn,
        )
        .unwrap();
        assert_eq!(out.as_str(), "ab12");
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
            false,
            fail_stdin,
            fail_warn,
        )
        .unwrap();
        assert_eq!(out.as_str(), "ab12");

        let out = resolve_required_secret(
            &INPUT_SPEC,
            sources(None, None, true),
            false,
            || Ok(wiping("cd34\r\n")),
            fail_warn,
        )
        .unwrap();
        assert_eq!(out.as_str(), "cd34");
    }

    // T14: one UTF-8 BOM plus surrounding whitespace normalizes away in
    // wiping storage (file and stdin); the bytes are otherwise unchanged.
    #[test]
    fn bom_and_whitespace_normalize_in_wiping_storage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input.hex");
        std::fs::write(&path, "\u{FEFF}  ab12\t\n").unwrap();
        let out = resolve_required_secret(
            &INPUT_SPEC,
            sources(None, Some(path), false),
            false,
            fail_stdin,
            fail_warn,
        )
        .unwrap();
        assert_eq!(out.as_str(), "ab12");

        let out = resolve_required_secret(
            &DATA_SPEC,
            sources(None, None, true),
            false,
            || Ok(wiping("\u{FEFF}cd34  ")),
            fail_warn,
        )
        .unwrap();
        assert_eq!(out.as_str(), "cd34");

        // A BOM alone (nothing but trimmable content) is an empty secret.
        let err = resolve_required_secret(
            &INPUT_SPEC,
            sources(None, None, true),
            false,
            || Ok(wiping("\u{FEFF} \t\n")),
            fail_warn,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("empty secret"), "must reject loudly: {err}");
        assert!(!err.contains('\u{FEFF}'), "must not echo the body: {err}");
    }

    // W1-C11-15: two argv-explicit sources are a loud error, not silent
    // precedence; an env-filled inline stays a quiet fallback under an
    // explicit file/stdin choice.
    #[test]
    fn conflicting_argv_sources_error_env_fallback_yields() {
        for (extra, inline_argv) in [
            (sources(Some("aa"), Some(PathBuf::from("f")), false), true),
            (sources(Some("aa"), None, true), true),
            (sources(None, Some(PathBuf::from("f")), true), false),
        ] {
            let err =
                resolve_required_secret(&INPUT_SPEC, extra, inline_argv, fail_stdin, fail_warn)
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
            false,
            fail_stdin,
            fail_warn,
        )
        .unwrap();
        assert_eq!(out.as_str(), "bb");

        // Env-filled inline + explicit stdin: stdin wins, no conflict.
        let out = resolve_required_secret(
            &INPUT_SPEC,
            sources(Some("aa"), None, true),
            false,
            || Ok(wiping("cc\n")),
            fail_warn,
        )
        .unwrap();
        assert_eq!(out.as_str(), "cc");
    }

    // W1-C11-15: missing required secrets error naming every source;
    // missing optional secrets resolve to None.
    #[test]
    fn missing_required_errors_optional_yields_none() {
        let err = resolve_required_secret(
            &INPUT_SPEC,
            sources(None, None, false),
            false,
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
            false,
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
                false,
                fail_stdin,
                fail_warn,
            )
            .is_err()
        );
        assert!(
            resolve_required_secret(
                &INPUT_SPEC,
                sources(None, None, true),
                false,
                || Ok(wiping("  \n")),
                fail_warn,
            )
            .is_err()
        );
        assert!(
            resolve_optional_secret(
                &VALUE_SPEC,
                sources(None, None, true),
                false,
                || Ok(wiping("")),
                fail_warn,
            )
            .is_err()
        );
    }

    // T14: a mid-stream read failure surfaces the source, never the
    // partial bytes; the partial body stays inside the dropped wiping
    // owner by construction (the reader below yields a secret prefix,
    // then fails).
    #[test]
    fn partial_read_errors_name_source_not_bytes() {
        struct FailAfterPrefix {
            prefix: &'static [u8],
            failed: bool,
        }

        impl std::io::Read for FailAfterPrefix {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.failed {
                    return Err(std::io::Error::other("boom"));
                }
                self.failed = true;
                let len = self.prefix.len().min(buf.len());
                buf[..len].copy_from_slice(&self.prefix[..len]);
                Ok(len)
            }
        }

        let mut reader = FailAfterPrefix { prefix: b"ab12ffff", failed: false };
        let err = read_external_string(&mut reader, "--input-stdin").unwrap_err().to_string();
        assert!(err.contains("--input-stdin"), "must name the source: {err}");
        assert!(err.contains("boom"), "must carry the I/O cause: {err}");
        assert!(!err.contains("ab12"), "must not echo partial bytes: {err}");

        // The injected stdin seam reports reader errors the same way.
        let err = resolve_required_secret(
            &INPUT_SPEC,
            sources(None, None, true),
            false,
            || Err("cannot read --input-stdin: boom".to_string().into()),
            fail_warn,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("--input-stdin"), "must name the source: {err}");
    }

    // T14: hex decodes into a wiping owner with unchanged bytes; an
    // invalid digit after a valid prefix, an odd length, and empty input
    // behave exactly like `hex::decode` without echoing the input.
    #[test]
    fn hex_decode_matches_plain_decoder_without_echo() {
        let canary = "ab12ZZ";
        let err = decode_hex_secret(&wiping(canary), "Invalid hex input").unwrap_err().to_string();
        assert_eq!(
            err,
            format!("Invalid hex input: {}", hex::decode(canary).unwrap_err()),
            "invalid digit must match hex::decode"
        );
        assert!(!err.contains(canary), "must not echo the input: {err}");

        for odd in ["a", "abc"] {
            let err = decode_hex_secret(&wiping(odd), "Invalid hex input").unwrap_err().to_string();
            assert_eq!(
                err,
                format!("Invalid hex input: {}", hex::decode(odd).unwrap_err()),
                "odd length must match hex::decode"
            );
        }

        let out = decode_hex_secret(&wiping("ab12"), "Invalid hex input").unwrap();
        out.expose(|bytes| assert_eq!(bytes, &[0xAB, 0x12]));
        let empty = decode_hex_secret(&wiping(""), "Invalid hex input").unwrap();
        assert!(empty.is_empty(), "empty hex stays empty (as hex::decode)");
    }

    // W1-L2-11: PINs resolve from argv (warned), env (silent), or stdin
    // (silent, wiping storage); argv+stdin collide loudly.
    #[test]
    fn pin_resolution_warns_on_argv_only() {
        let mut warned = Vec::new();
        let pin =
            resolve_required_pin(Some(SecretBytes::from("1234")), false, true, fail_stdin, |m| {
                warned.push(m)
            })
            .unwrap();
        pin.expose(|b| assert_eq!(b, b"1234"));
        assert_eq!(warned.len(), 1, "argv PIN must warn");

        let pin = resolve_required_pin(
            Some(SecretBytes::from("1234")),
            false,
            false,
            fail_stdin,
            fail_warn,
        )
        .unwrap();
        pin.expose(|b| assert_eq!(b, b"1234"));

        let pin =
            resolve_required_pin(None, true, false, || Ok(wiping("5678\n")), fail_warn).unwrap();
        pin.expose(|b| assert_eq!(b, b"5678"));

        let err = resolve_required_pin(
            Some(SecretBytes::from("1234")),
            true,
            true,
            fail_stdin,
            fail_warn,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("--pin-stdin"), "must name spellings: {err}");

        let err = resolve_required_pin(None, false, false, fail_stdin, fail_warn)
            .unwrap_err()
            .to_string();
        for spelling in ["--pin", "--pin-stdin", "PKCS11_PROXY_PIN"] {
            assert!(err.contains(spelling), "must name {spelling}: {err}");
        }
        assert!(resolve_optional_pin(None, false, false, fail_stdin, fail_warn).unwrap().is_none());
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
            true,
            |m| warned.push(m),
        )
        .unwrap();
        pin.expose(|b| assert_eq!(b, b"so"));
        assert_eq!(warned.len(), 1, "argv SO PIN must warn");

        resolve_required_inline_pin(
            Some(SecretBytes::from("so")),
            "so-pin",
            "PKCS11_PROXY_SO_PIN",
            false,
            fail_warn,
        )
        .unwrap();

        let err =
            resolve_required_inline_pin(None, "new-pin", "PKCS11_PROXY_NEW_PIN", false, fail_warn)
                .unwrap_err()
                .to_string();
        assert!(err.contains("PKCS11_PROXY_NEW_PIN"), "must name env: {err}");
    }
}
