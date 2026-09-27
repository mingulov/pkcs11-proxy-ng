# RPM spec for pkcs11-proxy-ng on Amazon Linux 2023.
#
# Subpackages mirror the Alpine APK layout:
#   * pkcs11-proxy-ng-shim    — client-side PKCS#11 module (.so)
#   * pkcs11-proxy-ng-daemon  — gRPC server binary + default configs
#   * pkcs11-proxy-ng-cli     — admin / smoke-test CLI
#   * pkcs11-proxy-ng-compat  — legacy symlinks
#
# The spec builds the complete source tar staged by Dockerfile.amazon.
# The build and notice collection run inside rpmbuild with pinned rustup
# tools and the explicitly namespaced Python 3.11 interpreter.

Name:           pkcs11-proxy-ng
Version:        0.2.0
Release:        1%{?dist}
Summary:        Rust PKCS#11 remote proxy

License:        Apache-2.0 OR MIT
URL:            https://github.com/mingulov/pkcs11-proxy-ng
Source0:        pkcs11-proxy-ng-%{version}.tar.gz

BuildArch:      x86_64
# `cargo` and `rust` are NOT listed in BuildRequires: the
# Dockerfile.amazon installs a rustup-managed toolchain (AL2023 stock
# rust is below transitive dep MSRV). The rustup cargo is on PATH
# when rpmbuild runs %build below. systemd-rpm-macros gives us the
# %{_unitdir} macro used in the daemon subpackage's file list.
BuildRequires:  protobuf-compiler systemd-rpm-macros python3.11
Requires:       glibc

%define _enable_debug_packages 0
%define debug_package %{nil}

%description
Memory-safe Rust implementation of a PKCS#11 remote proxy. Forwards
PKCS#11 operations from client applications to a backend HSM or
software token over gRPC. This umbrella package is empty — install
one of the subpackages: -shim (client side), -daemon (server),
-cli (admin tooling), -compat (legacy symlinks).

# ─── Subpackages ───────────────────────────────────────────────────────────

%package shim
Summary:        %{summary} (client-side PKCS#11 module)
%description shim
Loadable PKCS#11 v2.40 / v3.0 / v3.2 shim library that consumer
applications load to talk to a pkcs11-proxy-ng daemon over gRPC.
Installs %{_libdir}/pkcs11/libpkcs11_proxy_ng_shim.so.

%package daemon
Summary:        %{summary} (gRPC server daemon)
Requires:       systemd
%description daemon
gRPC server daemon that dlopens a backend PKCS#11 .so and proxies
operations from connected shim clients. Installs the binary
%{_bindir}/pkcs11-proxy-ng, default configs under
%{_sysconfdir}/pkcs11-proxy-ng/, and a systemd unit (disabled by
default — operators must edit the backend module path before
enabling the unit).

%package cli
Summary:        %{summary} (admin / smoke-test CLI)
%description cli
Administrative CLI for managing the daemon, inspecting backend
capabilities, and running smoke tests. Installs
%{_bindir}/pkcs11-proxy-ng-cli.

%package compat
Summary:        %{summary} (legacy libpkcs11-proxy.so symlink)
Requires:       %{name}-shim = %{version}-%{release}
%description compat
Creates %{_libdir}/libpkcs11-proxy.so as a symlink to the new shim,
so consumer Dockerfiles using the legacy path keep working without
a full Dockerfile rewrite. Consumers must still switch their
connection env var to PKCS11_PROXY_ENDPOINT
(or PKCS11_PROXY_SOCKET=tcp://..., which the new shim accepts as a
back-compat alias).

# ─── Build ─────────────────────────────────────────────────────────────────

%prep
%setup -q -n %{name}-%{version}

%build
# Build from the staged workspace source and record local workspace notice
# inputs. These RPMs make no registry-source binary provenance claim.
cargo build --release --workspace --locked
python3.11 scripts/release_checks.py workspace-notices \
    --binaries target/release \
    --target "$(rustc -vV | awk '/^host:/ {print $2}')" \
    --inputs-output target/package-notice-inputs \
    --output target/package-notices

%install
install -d %{buildroot}%{_bindir}
install -d %{buildroot}%{_libdir}/pkcs11
install -d %{buildroot}%{_libdir}
install -d %{buildroot}%{_sysconfdir}/pkcs11-proxy-ng
install -d %{buildroot}%{_unitdir}

install -m 0755 target/release/libpkcs11_proxy_ng_shim.so \
    %{buildroot}%{_libdir}/pkcs11/libpkcs11_proxy_ng_shim.so
install -m 0755 target/release/pkcs11-proxy-ng \
    %{buildroot}%{_bindir}/pkcs11-proxy-ng
install -m 0755 target/release/pkcs11-proxy-ng-cli \
    %{buildroot}%{_bindir}/pkcs11-proxy-ng-cli

install -m 0644 packaging/config/proxy.toml.default \
    %{buildroot}%{_sysconfdir}/pkcs11-proxy-ng/proxy.toml
install -m 0644 crates/types/src/mechanism_params_default.toml \
    %{buildroot}%{_sysconfdir}/pkcs11-proxy-ng/mechanism_params.toml
install -m 0644 packaging/config/mechanism_params.cloudhsm.toml.example \
    %{buildroot}%{_sysconfdir}/pkcs11-proxy-ng/mechanism_params.cloudhsm.toml.example
install -m 0644 packaging/amazon/pkcs11-proxy-ng.service \
    %{buildroot}%{_unitdir}/pkcs11-proxy-ng.service

ln -sf pkcs11/libpkcs11_proxy_ng_shim.so \
    %{buildroot}%{_libdir}/libpkcs11-proxy.so

for part in shim daemon cli; do
    notice_dir="%{buildroot}%{_licensedir}/%{name}-$part"
    install -d "$notice_dir"
    install -m 0644 LICENSE-APACHE LICENSE-MIT \
        target/package-notices/THIRD_PARTY_NOTICES \
        target/package-notices/notice-inventory.json \
        target/package-notice-inputs/build-provenance.json "$notice_dir/"
    cp -a target/package-notices/license-material "$notice_dir/"
done

# ─── File manifests ────────────────────────────────────────────────────────

%files
# umbrella owns nothing

%files shim
%{_libdir}/pkcs11/libpkcs11_proxy_ng_shim.so
%license %{_licensedir}/%{name}-shim/LICENSE-APACHE
%license %{_licensedir}/%{name}-shim/LICENSE-MIT
%license %{_licensedir}/%{name}-shim/THIRD_PARTY_NOTICES
%license %{_licensedir}/%{name}-shim/license-material
%license %{_licensedir}/%{name}-shim/notice-inventory.json
%license %{_licensedir}/%{name}-shim/build-provenance.json

%files daemon
%{_bindir}/pkcs11-proxy-ng
%license %{_licensedir}/%{name}-daemon/LICENSE-APACHE
%license %{_licensedir}/%{name}-daemon/LICENSE-MIT
%license %{_licensedir}/%{name}-daemon/THIRD_PARTY_NOTICES
%license %{_licensedir}/%{name}-daemon/license-material
%license %{_licensedir}/%{name}-daemon/notice-inventory.json
%license %{_licensedir}/%{name}-daemon/build-provenance.json
%config(noreplace) %{_sysconfdir}/pkcs11-proxy-ng/proxy.toml
%config(noreplace) %{_sysconfdir}/pkcs11-proxy-ng/mechanism_params.toml
%{_sysconfdir}/pkcs11-proxy-ng/mechanism_params.cloudhsm.toml.example
%{_unitdir}/pkcs11-proxy-ng.service

%files cli
%{_bindir}/pkcs11-proxy-ng-cli
%license %{_licensedir}/%{name}-cli/LICENSE-APACHE
%license %{_licensedir}/%{name}-cli/LICENSE-MIT
%license %{_licensedir}/%{name}-cli/THIRD_PARTY_NOTICES
%license %{_licensedir}/%{name}-cli/license-material
%license %{_licensedir}/%{name}-cli/notice-inventory.json
%license %{_licensedir}/%{name}-cli/build-provenance.json

%files compat
%{_libdir}/libpkcs11-proxy.so

# ─── Scriptlets ────────────────────────────────────────────────────────────

%post daemon
cat <<'EOF'

pkcs11-proxy-ng-daemon installed.

NEXT STEPS:
1. Edit /etc/pkcs11-proxy-ng/proxy.toml and replace the
   [backend].module placeholder with a real PKCS#11 .so path.
2. Start the service:    systemctl start pkcs11-proxy-ng
3. Enable on boot:       systemctl enable pkcs11-proxy-ng

The default config listens on 0.0.0.0:7512 with auth="none". This is
intended for deployments behind external network protection. Switch
to mTLS via the commented template in proxy.toml if you cannot
guarantee the network boundary.
EOF
exit 0

%changelog
* Wed May 20 2026 Denis Mingulov (project maintainer) - 0.2.0-1
- Initial pkcs11-proxy-ng RPM release. Server-driven mechanism
  registry, three-way subpackage split, optional -compat layer.
