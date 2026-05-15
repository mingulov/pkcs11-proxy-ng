use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, OnceLock};

use tempfile::TempDir;
use tokio::sync::OwnedMutexGuard;

static REAL_BACKEND_LOCK: OnceLock<Arc<tokio::sync::Mutex<()>>> = OnceLock::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SoLoginMode {
    ProvidedPin,
    EmptyPin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenSetupMode {
    Preinitialized,
    InitTokenAndUserPin { so_login: SoLoginMode },
}

fn real_backend_lock() -> Arc<tokio::sync::Mutex<()>> {
    REAL_BACKEND_LOCK.get_or_init(|| Arc::new(tokio::sync::Mutex::new(()))).clone()
}

fn find_first_existing_path(candidates: &[&str]) -> Option<PathBuf> {
    candidates.iter().map(Path::new).find(|path| path.exists()).map(Path::to_path_buf)
}

fn required_provider_env(prefix: &str, suffix: &str) -> Result<String, String> {
    let key = format!("{prefix}_{suffix}");
    std::env::var(&key).map_err(|err| match err {
        std::env::VarError::NotPresent => format!("{key} is not set"),
        std::env::VarError::NotUnicode(_) => format!("{key} is not valid UTF-8"),
    })
}

pub struct ProviderFixture {
    pub name: &'static str,
    pub module_path: PathBuf,
    pub initialize_args: Option<String>,
    pub token_label: String,
    pub user_pin: String,
    pub so_pin: String,
    token_setup: TokenSetupMode,
    _softhsm2_conf: Option<ScopedEnvVar>,
    _guard: OwnedMutexGuard<()>,
    _temp_dir: Option<TempDir>,
}

struct ScopedEnvVar {
    key: &'static str,
    previous: Option<OsString>,
}

impl ScopedEnvVar {
    fn set_path(key: &'static str, value: &Path) -> Self {
        let previous = std::env::var_os(key);
        unsafe {
            std::env::set_var(key, value);
        }
        Self { key, previous }
    }
}

impl Drop for ScopedEnvVar {
    fn drop(&mut self) {
        unsafe {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }
}

impl ProviderFixture {
    pub async fn soft_hsm() -> Result<Self, String> {
        let guard = real_backend_lock().lock_owned().await;
        let module_path = find_first_existing_path(&[
            "/usr/lib/softhsm/libsofthsm2.so",
            "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
            "/usr/local/lib/softhsm/libsofthsm2.so",
            "/usr/lib64/softhsm/libsofthsm2.so",
            "/usr/lib64/pkcs11/libsofthsm2.so",
            "/usr/lib64/libsofthsm2.so",
        ])
        .ok_or_else(|| "libsofthsm2.so not found".to_string())?;

        let temp_dir = tempfile::tempdir().map_err(|e| format!("tempdir failed: {e}"))?;
        let conf_path = temp_dir.path().join("softhsm2.conf");
        let tokens_dir = temp_dir.path().join("tokens");
        std::fs::create_dir_all(&tokens_dir)
            .map_err(|e| format!("create tokens dir failed: {e}"))?;
        std::fs::write(
            &conf_path,
            format!(
                "directories.tokendir = {}\nobjectstore.backend = file\n",
                tokens_dir.display()
            ),
        )
        .map_err(|e| format!("write softhsm2.conf failed: {e}"))?;

        let softhsm2_conf = ScopedEnvVar::set_path("SOFTHSM2_CONF", &conf_path);

        let token_label = "test-token".to_string();
        let user_pin = "1234".to_string();
        let so_pin = "5678".to_string();

        let output = Command::new("softhsm2-util")
            .args([
                "--init-token",
                "--slot",
                "0",
                "--label",
                &token_label,
                "--pin",
                &user_pin,
                "--so-pin",
                &so_pin,
            ])
            .output()
            .map_err(|e| format!("softhsm2-util launch failed: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "softhsm2-util failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(Self {
            name: "softhsm2",
            module_path,
            initialize_args: None,
            token_label,
            user_pin,
            so_pin,
            token_setup: TokenSetupMode::Preinitialized,
            _softhsm2_conf: Some(softhsm2_conf),
            _guard: guard,
            _temp_dir: Some(temp_dir),
        })
    }

    pub async fn soft_hsm_multi_slot(slot_count: usize) -> Result<Self, String> {
        let guard = real_backend_lock().lock_owned().await;
        let module_path = find_first_existing_path(&[
            "/usr/lib/softhsm/libsofthsm2.so",
            "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
            "/usr/local/lib/softhsm/libsofthsm2.so",
            "/usr/lib64/softhsm/libsofthsm2.so",
            "/usr/lib64/pkcs11/libsofthsm2.so",
            "/usr/lib64/libsofthsm2.so",
        ])
        .ok_or_else(|| "libsofthsm2.so not found".to_string())?;

        let temp_dir = tempfile::tempdir().map_err(|e| format!("tempdir failed: {e}"))?;
        let conf_path = temp_dir.path().join("softhsm2.conf");
        let tokens_dir = temp_dir.path().join("tokens");
        std::fs::create_dir_all(&tokens_dir)
            .map_err(|e| format!("create tokens dir failed: {e}"))?;
        std::fs::write(
            &conf_path,
            format!(
                "directories.tokendir = {}\nobjectstore.backend = file\n",
                tokens_dir.display()
            ),
        )
        .map_err(|e| format!("write softhsm2.conf failed: {e}"))?;

        let softhsm2_conf = ScopedEnvVar::set_path("SOFTHSM2_CONF", &conf_path);

        let user_pin = "1234".to_string();
        let so_pin = "5678".to_string();

        for i in 0..slot_count {
            let label = format!("slot-{i}");
            let output = Command::new("softhsm2-util")
                .args([
                    "--init-token",
                    "--slot",
                    &i.to_string(),
                    "--label",
                    &label,
                    "--pin",
                    &user_pin,
                    "--so-pin",
                    &so_pin,
                ])
                .output()
                .map_err(|e| format!("softhsm2-util launch failed: {e}"))?;
            if !output.status.success() {
                return Err(format!(
                    "softhsm2-util slot {i} failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
        }

        Ok(Self {
            name: "softhsm2-multi",
            module_path,
            initialize_args: None,
            token_label: "slot-0".to_string(),
            user_pin,
            so_pin,
            token_setup: TokenSetupMode::Preinitialized,
            _softhsm2_conf: Some(softhsm2_conf),
            _guard: guard,
            _temp_dir: Some(temp_dir),
        })
    }

    pub async fn nss_softokn() -> Result<Self, String> {
        let guard = real_backend_lock().lock_owned().await;
        let module_path = find_first_existing_path(&[
            "/lib/x86_64-linux-gnu/libsoftokn3.so",
            "/usr/lib/x86_64-linux-gnu/libsoftokn3.so",
            "/usr/lib64/libsoftokn3.so",
        ])
        .ok_or_else(|| "libsoftokn3.so not found".to_string())?;

        let temp_dir = tempfile::tempdir().map_err(|e| format!("tempdir failed: {e}"))?;
        let nssdb_dir = temp_dir.path().join("nssdb");
        std::fs::create_dir_all(&nssdb_dir)
            .map_err(|e| format!("create NSS db dir failed: {e}"))?;

        let token_label = "test-token".to_string();
        let user_pin = "1234".to_string();
        let so_pin = "5678".to_string();
        let initialize_args = format!(
            "configDir='sql:{}' certPrefix='' keyPrefix='' secmod='secmod.db' \
             flags=forceOpen,optimizeSpace tokenDescription='{}'",
            nssdb_dir.display(),
            token_label
        );

        Ok(Self {
            name: "nss-softokn",
            module_path,
            initialize_args: Some(initialize_args),
            token_label,
            user_pin,
            so_pin,
            token_setup: TokenSetupMode::InitTokenAndUserPin { so_login: SoLoginMode::EmptyPin },
            _softhsm2_conf: None,
            _guard: guard,
            _temp_dir: Some(temp_dir),
        })
    }

    pub async fn nss_from_env() -> Result<Self, String> {
        Self::from_env("PKCS11_PROXY_NSS", "nss-softokn", Some("PKCS11_PROXY_NSS_INIT_ARGS")).await
    }

    pub async fn kryoptic_from_env() -> Result<Self, String> {
        Self::from_env("PKCS11_PROXY_KRYOPTIC", "kryoptic", Some("PKCS11_PROXY_KRYOPTIC_INIT_ARGS"))
            .await
    }

    async fn from_env(
        prefix: &str,
        name: &'static str,
        init_args_env: Option<&str>,
    ) -> Result<Self, String> {
        let guard = real_backend_lock().lock_owned().await;
        let module_key = format!("{prefix}_MODULE");
        let module_path = std::env::var_os(&module_key)
            .map(PathBuf::from)
            .ok_or_else(|| format!("{module_key} is not set"))?;
        if !module_path.exists() {
            return Err(format!("{module_key} points to missing path: {}", module_path.display()));
        }
        let token_label = required_provider_env(prefix, "TOKEN_LABEL")?;
        let user_pin = required_provider_env(prefix, "USER_PIN")?;
        let so_pin = required_provider_env(prefix, "SO_PIN")?;
        let initialize_args = init_args_env.and_then(|key| std::env::var(key).ok());
        let empty_so_pin = matches!(
            std::env::var(format!("{prefix}_EMPTY_SO_PIN")).ok().as_deref(),
            Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
        );
        let token_setup = match std::env::var(format!("{prefix}_INIT_TOKEN")).ok().as_deref() {
            Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES") => {
                TokenSetupMode::InitTokenAndUserPin {
                    so_login: if empty_so_pin {
                        SoLoginMode::EmptyPin
                    } else {
                        SoLoginMode::ProvidedPin
                    },
                }
            }
            _ => TokenSetupMode::Preinitialized,
        };

        Ok(Self {
            name,
            module_path,
            initialize_args,
            token_label,
            user_pin,
            so_pin,
            token_setup,
            _softhsm2_conf: None,
            _guard: guard,
            _temp_dir: None,
        })
    }

    pub(crate) fn token_setup_state(&self) -> TokenSetupState {
        match self.token_setup {
            TokenSetupMode::Preinitialized => TokenSetupState::Preinitialized,
            TokenSetupMode::InitTokenAndUserPin { so_login } => {
                TokenSetupState::InitTokenAndUserPin { so_login }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TokenSetupState {
    Preinitialized,
    InitTokenAndUserPin { so_login: SoLoginMode },
}

impl TokenSetupState {
    pub(crate) fn so_pin_bytes(self, fixture: &ProviderFixture) -> &[u8] {
        match self {
            Self::Preinitialized => fixture.so_pin.as_bytes(),
            Self::InitTokenAndUserPin { so_login } => match so_login {
                SoLoginMode::ProvidedPin => fixture.so_pin.as_bytes(),
                SoLoginMode::EmptyPin => &[],
            },
        }
    }
}
