#!/usr/bin/env bash
# collect-debug-bundle.sh — Gather diagnostic info for reproducing failures.
#
# Usage:
#   scripts/collect-debug-bundle.sh [--output-dir DIR] [--include-logs DIR]
#
# Produces a timestamped tarball in the output directory containing:
#   - System and toolchain versions
#   - Cargo workspace metadata
#   - PKCS#11 provider availability
#   - Build/test environment variables
#   - Optional log files
#
# Designed to be called standalone or from test-matrix.sh on failure.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUTPUT_DIR="${ROOT_DIR}/target/debug-bundles"
INCLUDE_LOGS=""

usage() {
    cat <<'EOF'
Usage: scripts/collect-debug-bundle.sh [options]

Options:
  --output-dir DIR       Write bundle to DIR (default: target/debug-bundles/)
  --include-logs DIR     Include log files from DIR in the bundle
  -h, --help             Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --include-logs)
            INCLUDE_LOGS="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

mkdir -p "$OUTPUT_DIR"
BUNDLE_DIR="$(mktemp -d)"
BUNDLE_NAME="debug-bundle-${TIMESTAMP}"
BD="$BUNDLE_DIR/$BUNDLE_NAME"
mkdir -p "$BD"

section() {
    local file="$1"
    local label="$2"
    echo "=== $label ===" >> "$BD/$file"
}

collect() {
    local file="$1"
    local label="$2"
    shift 2
    section "$file" "$label"
    if "$@" >> "$BD/$file" 2>&1; then
        echo "" >> "$BD/$file"
    else
        echo "(command failed with exit code $?)" >> "$BD/$file"
        echo "" >> "$BD/$file"
    fi
}

redact_pkcs11_proxy_env() {
    env | awk -F= '
        BEGIN { IGNORECASE = 1 }
        /^PKCS11_PROXY/ {
            name = $1
            upper = toupper(name)
            sensitive = 0
            if (upper == "PKCS11_PROXY_PIN") sensitive = 1
            if (upper == "PKCS11_PROXY_SO_PIN") sensitive = 1
            if (upper == "PKCS11_PROXY_NEW_PIN") sensitive = 1
            if (upper == "PKCS11_PROXY_SEED") sensitive = 1
            if (upper == "PKCS11_PROXY_KRYOPTIC_USER_PIN") sensitive = 1
            if (upper == "PKCS11_PROXY_KRYOPTIC_SO_PIN") sensitive = 1
            if (upper == "PKCS11_PROXY_KRYOPTIC_INIT_ARGS") sensitive = 1
            if (upper == "PKCS11_PROXY_NSS_USER_PIN") sensitive = 1
            if (upper == "PKCS11_PROXY_NSS_SO_PIN") sensitive = 1
            if (upper == "PKCS11_PROXY_NSS_INIT_ARGS") sensitive = 1
            if (upper == "PKCS11_PROXY_TLS_CLIENT_KEY") sensitive = 1
            if (upper == "PKCS11_PROXY_TLS_SERVER_KEY") sensitive = 1
            if (upper == "PKCS11_PROXY_TLS_KEY") sensitive = 1
            if (upper ~ /(^|_)PIN$/) sensitive = 1
            if (upper ~ /(_USER_PIN|_SO_PIN|_NEW_PIN)$/) sensitive = 1
            if (upper ~ /(PASSWORD|SECRET|PRIVATE)/) sensitive = 1
            if (upper ~ /(SERVER_KEY|KEY_FILE)$/) sensitive = 1
            if (upper ~ /_KEY$/) sensitive = 1
            if (upper ~ /_INIT_ARGS$/) sensitive = 1
            if (sensitive) {
                print name "=<redacted>"
            } else {
                print
            }
        }
    ' | sort
}

# ── System info ──────────────────────────────────────────────────────
echo "[debug-bundle] Collecting system info..."
{
    section "system.txt" "Hostname"
    hostname 2>/dev/null || echo "(unknown)"
    echo ""
    section "system.txt" "Date (UTC)"
    date -u
    echo ""
    section "system.txt" "Kernel"
    uname -a
    echo ""
    section "system.txt" "OS Release"
    cat /etc/os-release 2>/dev/null || echo "(not available)"
    echo ""
    section "system.txt" "CPU"
    nproc 2>/dev/null || echo "(unknown)"
    echo ""
    section "system.txt" "Memory"
    free -h 2>/dev/null || echo "(not available)"
    echo ""
    section "system.txt" "Disk (workspace)"
    df -h "$ROOT_DIR" 2>/dev/null || echo "(not available)"
} > "$BD/system.txt" 2>&1

# ── Toolchain info ───────────────────────────────────────────────────
echo "[debug-bundle] Collecting toolchain info..."
{
    collect "toolchain.txt" "rustc" rustc --version --verbose
    collect "toolchain.txt" "cargo" cargo --version
    collect "toolchain.txt" "rustup" rustup show
    collect "toolchain.txt" "protoc" protoc --version
    collect "toolchain.txt" "pkg-config" pkg-config --version
} 2>/dev/null

# ── Workspace metadata ───────────────────────────────────────────────
echo "[debug-bundle] Collecting workspace metadata..."
cd "$ROOT_DIR"
{
    section "workspace.txt" "Git HEAD"
    git log --oneline -5 2>/dev/null || echo "(not a git repo)"
    echo ""
    section "workspace.txt" "Git status"
    git status --short 2>/dev/null || echo "(not a git repo)"
    echo ""
    section "workspace.txt" "Git diff (stat)"
    git diff --stat 2>/dev/null || echo "(not a git repo)"
    echo ""
    section "workspace.txt" "Cargo workspace members"
    cargo metadata --no-deps --format-version 1 2>/dev/null | \
        python3 -c "import sys,json; [print(p['name'],p['version']) for p in json.load(sys.stdin)['packages']]" 2>/dev/null || \
        echo "(cargo metadata failed)"
} > "$BD/workspace.txt" 2>&1

# ── PKCS#11 provider availability ────────────────────────────────────
echo "[debug-bundle] Checking PKCS#11 provider availability..."
{
    section "providers.txt" "SoftHSM2"
    for path in \
        /usr/lib/softhsm/libsofthsm2.so \
        /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
        /usr/local/lib/softhsm/libsofthsm2.so \
        /usr/lib64/softhsm/libsofthsm2.so \
        /usr/lib64/pkcs11/libsofthsm2.so; do
        if [[ -f "$path" ]]; then
            echo "  found: $path"
        fi
    done
    if command -v softhsm2-util >/dev/null 2>&1; then
        echo "  softhsm2-util: $(softhsm2-util --version 2>&1 || echo 'present')"
    else
        echo "  softhsm2-util: NOT FOUND"
    fi
    echo ""

    section "providers.txt" "NSS softokn"
    for path in \
        /usr/lib/x86_64-linux-gnu/nss/libsoftokn3.so \
        /usr/lib64/libsoftokn3.so \
        /usr/lib64/nss/libsoftokn3.so; do
        if [[ -f "$path" ]]; then
            echo "  found: $path"
        fi
    done
    echo ""

    section "providers.txt" "Kryoptic"
    if [[ -f /opt/kryoptic/target/release/libkryoptic_pkcs11.so ]]; then
        echo "  found: /opt/kryoptic/target/release/libkryoptic_pkcs11.so"
    else
        echo "  NOT FOUND"
    fi
    echo ""

    section "providers.txt" "PKCS#11 tools"
    for tool in pkcs11-tool p11tool pkcs11test openssl; do
        if command -v "$tool" >/dev/null 2>&1; then
            echo "  $tool: $(command -v "$tool")"
        else
            echo "  $tool: NOT FOUND"
        fi
    done
    echo ""

    section "providers.txt" "OpenSSL pkcs11 provider"
    for path in \
        /usr/lib64/ossl-modules/pkcs11prov.so \
        /usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11prov.so \
        /usr/local/lib64/ossl-modules/pkcs11prov.so \
        /usr/local/lib/ossl-modules/pkcs11prov.so; do
        if [[ -f "$path" ]]; then
            echo "  found: $path"
        fi
    done
} > "$BD/providers.txt" 2>&1

# ── Environment variables ────────────────────────────────────────────
echo "[debug-bundle] Collecting relevant environment variables..."
{
    section "environment.txt" "PKCS11_PROXY_* variables"
    redact_pkcs11_proxy_env || echo "(none set)"
    echo ""
    section "environment.txt" "SOFTHSM2_CONF"
    echo "${SOFTHSM2_CONF:-(not set)}"
    echo ""
    section "environment.txt" "Rust/Cargo variables"
    env | grep -E "^(CARGO_|RUST|OPENSSL_)" | sort || echo "(none set)"
    echo ""
    section "environment.txt" "PATH"
    echo "$PATH" | tr ':' '\n'
} > "$BD/environment.txt" 2>&1

# ── Build artifacts ──────────────────────────────────────────────────
echo "[debug-bundle] Checking build artifacts..."
{
    TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT_DIR/target}"
    section "artifacts.txt" "Daemon binary"
    if [[ -x "$TARGET_DIR/debug/pkcs11-proxy-ng" ]]; then
        ls -la "$TARGET_DIR/debug/pkcs11-proxy-ng"
        file "$TARGET_DIR/debug/pkcs11-proxy-ng" 2>/dev/null || true
    else
        echo "NOT FOUND at $TARGET_DIR/debug/pkcs11-proxy-ng"
    fi
    echo ""

    section "artifacts.txt" "Shim library"
    shim="$(find "$TARGET_DIR"/debug -maxdepth 1 -name 'libpkcs11_proxy_ng_shim.so' -print -quit 2>/dev/null || true)"
    if [[ -n "$shim" && -f "$shim" ]]; then
        ls -la "$shim"
        file "$shim" 2>/dev/null || true
    else
        echo "NOT FOUND under $TARGET_DIR/debug/"
    fi
    echo ""

    section "artifacts.txt" "Test binaries"
    find "$TARGET_DIR/debug/deps" -maxdepth 1 -executable -name '*test*' -newer "$TARGET_DIR" 2>/dev/null | head -20 || echo "(none)"
} > "$BD/artifacts.txt" 2>&1

# ── Include log files if requested ───────────────────────────────────
if [[ -n "$INCLUDE_LOGS" && -d "$INCLUDE_LOGS" ]]; then
    echo "[debug-bundle] Including logs from $INCLUDE_LOGS..."
    mkdir -p "$BD/logs"
    find "$INCLUDE_LOGS" -maxdepth 2 -name '*.log' -o -name '*.txt' 2>/dev/null | \
        while read -r logfile; do
            # Limit each log to 10000 lines to avoid huge bundles
            tail -n 10000 "$logfile" > "$BD/logs/$(basename "$logfile")" 2>/dev/null || true
        done
fi

# ── Example configs snapshot ─────────────────────────────────────────
if [[ -d "$ROOT_DIR/examples" ]]; then
    echo "[debug-bundle] Including example configs..."
    mkdir -p "$BD/configs"
    cp "$ROOT_DIR"/examples/*.toml "$BD/configs/" 2>/dev/null || true
fi

# ── Create tarball ───────────────────────────────────────────────────
TARBALL="$OUTPUT_DIR/${BUNDLE_NAME}.tar.gz"
tar -czf "$TARBALL" -C "$BUNDLE_DIR" "$BUNDLE_NAME"
rm -rf "$BUNDLE_DIR"

echo "[debug-bundle] Bundle created: $TARBALL"
echo "[debug-bundle] Contents:"
tar -tzf "$TARBALL" | sed 's/^/  /'
