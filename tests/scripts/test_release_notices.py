"""Binary notice material and distribution carriage boundaries."""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from release.package_model import ReleaseError  # noqa: E402
from release import package_notices  # noqa: E402
from release.package_notices import collect_material, verified_dependency_archive  # noqa: E402
from release.package_bundles import stage_bundle  # noqa: E402


def digest(data):
    return hashlib.sha256(data).hexdigest()


class MaterialTests(unittest.TestCase):
    def test_workspace_feature_tree_records_shared_build_union(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            (repo / "Cargo.toml").write_text(
                '[workspace]\nmembers=["app_a","app_b","shared","server_leaf"]\nresolver="2"\n')
            manifests = {
                "app_a": '[dependencies]\nshared={path="../shared",features=["server"]}\n',
                "app_b": '[dependencies]\nshared={path="../shared"}\n',
                "shared": '[features]\nserver=["dep:server_leaf"]\n'
                          '[dependencies]\nserver_leaf={path="../server_leaf",optional=true}\n',
                "server_leaf": "",
            }
            for name, tail in manifests.items():
                root = repo / name
                (root / "src").mkdir(parents=True)
                (root / "src/lib.rs").write_text("pub fn fixture() {}\n")
                (root / "Cargo.toml").write_text(
                    f'[package]\nname="{name}"\nversion="0.1.0"\nedition="2024"\n{tail}')
            subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=repo,
                           capture_output=True, text=True, check=True)
            isolated = subprocess.run(
                ["cargo", "tree", "--locked", "--offline", "--target", "x86_64-unknown-linux-gnu",
                 "-p", "app_b", "-e", "normal,build", "--prefix", "none", "-f", "{p}|{f}"],
                cwd=repo, capture_output=True, text=True, check=True).stdout
            self.assertNotIn("server_leaf v0.1.0", isolated)
            features, packages = package_notices.workspace_feature_tree(
                repo, "x86_64-unknown-linux-gnu")
            self.assertIn("server", features["shared"])
            self.assertIn(("server_leaf", "0.1.0"), packages)

    def test_dependency_archive_requires_exact_version_and_lock_checksum(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            source = home / "registry/src/index/example-1.0.0"
            source.mkdir(parents=True)
            manifest = source / "Cargo.toml"
            manifest.write_text('[package]\nname="example"\nversion="1.0.0"\n')
            cache = home / "registry/cache/index"
            cache.mkdir(parents=True)
            archive = cache / "example-1.0.0.crate"
            archive.write_bytes(b"published bytes")
            locked = {"root": {("example", "1.0.0"): digest(archive.read_bytes())}}
            scopes = {"root": {"runtime"}}
            self.assertEqual(verified_dependency_archive("example", "1.0.0", manifest,
                                                         home, locked, scopes)[1],
                             digest(archive.read_bytes()))
            with self.assertRaises(ReleaseError):
                verified_dependency_archive("example", "2.0.0", manifest, home, locked, scopes)
            archive.write_bytes(b"changed")
            with self.assertRaises(ReleaseError):
                verified_dependency_archive("example", "1.0.0", manifest, home, locked, scopes)

    def test_missing_and_empty_upstream_material_fail(self):
        for entries in ({"src/lib.rs": b"code"}, {"LICENSE": b" \n"}):
            with self.subTest(entries=entries), self.assertRaises(ReleaseError):
                collect_material("example", "1.0.0", entries)

    def test_unsafe_material_path_fails(self):
        for path in ("../NOTICE", "LICENSE\nsmuggled", "bad\x00name"):
            with self.subTest(path=path), self.assertRaises(ReleaseError):
                collect_material("example", "1.0.0", {"LICENSE": b"text", path: b"bad"})

    def test_benign_dot_directories_in_published_crates_are_allowed(self):
        material = collect_material("example", "1.0.0",
                                    {"LICENSE": b"text", ".github/FUNDING.yml": b"ignored"})
        self.assertEqual(material["licenses/LICENSE"], b"text")

    def test_webpki_requires_distinct_compiled_file_notices(self):
        header_a = (b"// Copyright 2023 Daniel McCarney.\n//\n"
                    b"// Permission to use, copy, modify, and/or distribute this software.\n\n")
        header_b = (b"// Copyright 2022 Rafael Fern\xc3\xa1ndez L\xc3\xb3pez.\n//\n"
                    b"// Permission to use, copy, modify, and/or distribute this software.\n\n")
        entries = {"LICENSE": b"Copyright 2015 Brian Smith\nPermission text\n",
                   "src/lib.rs": b"mod crl;\nmod subject_name;\n",
                   "src/crl/mod.rs": header_a + b"fn a() {}\n",
                   "src/subject_name/mod.rs": header_b + b"fn b() {}\n",
                   "src/ring_algs.rs": b'#[cfg(test)]\n#[path = "."]\nmod tests {\n#[path = "alg_tests.rs"]\nmod alg_tests;\n}\n',
                   "src/aws_lc_rs_algs.rs": b'#[cfg(test)]\n#[path = "."]\nmod tests {\n#[path = "alg_tests.rs"]\nmod alg_tests;\n}\n',
                   "src/alg_tests.rs": b'include_bytes!("../third-party/chromium/data/verify_signed_data/foo");\n',
                   "src/subject_name/dns_name.rs": b'#[cfg(test)]\nmod tests {\n// adapted from Chromium\n}\n'}
        material = collect_material("rustls-webpki", "0.103.15", entries)
        self.assertEqual(material["headers/src/crl/mod.rs.txt"], header_a.rstrip() + b"\n")
        self.assertEqual(material["headers/src/subject_name/mod.rs.txt"], header_b.rstrip() + b"\n")
        del entries["src/subject_name/mod.rs"]
        with self.assertRaises(ReleaseError):
            collect_material("rustls-webpki", "0.103.15", entries)
        entries["src/subject_name/mod.rs"] = header_b
        entries["src/ring_algs.rs"] = b'mod tests {\n#[path = "alg_tests.rs"]\nmod alg_tests;\n}\n'
        with self.assertRaises(ReleaseError):
            collect_material("rustls-webpki", "0.103.15", entries)

    def test_ring_requires_subcomponent_material_and_full_source_supplement(self):
        entries = {"LICENSE": b"ring root\n", "LICENSE-other-bits": b"ISC\n",
                   "LICENSE-BoringSSL": b"Apache\n", "third_party/fiat/LICENSE": b"MIT\n",
                   "src/polyfill/once_cell/LICENSE-MIT": b"MIT\n",
                   "src/polyfill/once_cell/LICENSE-APACHE": b"Apache\n",
                   "src/foo.rs": b"// Copyright example\nfn foo() {}\n"}
        material = collect_material("ring", "0.17.14", entries)
        self.assertEqual(material["source-supplement/src/foo.rs"], entries["src/foo.rs"])
        for missing in ("LICENSE-other-bits", "LICENSE-BoringSSL", "third_party/fiat/LICENSE",
                        "src/polyfill/once_cell/LICENSE-MIT", "src/polyfill/once_cell/LICENSE-APACHE"):
            incomplete = dict(entries)
            del incomplete[missing]
            with self.subTest(missing=missing), self.assertRaises(ReleaseError):
                collect_material("ring", "0.17.14", incomplete)


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.binaries = self.base / "binaries"
        self.binaries.mkdir()
        self.notices = self.base / "notices"
        self.notices.mkdir()
        self.provenance = self.base / "build-provenance.json"
        self.inventory = self.notices / "notice-inventory.json"
        self.output = self.base / "out"
        self.target = "x86_64-unknown-linux-gnu"
        self.names = ("pkcs11-proxy-ng", "pkcs11-proxy-ng-cli", "libpkcs11_proxy_ng_shim.so")
        artifacts = []
        for name in self.names:
            data = ("binary:" + name).encode()
            (self.binaries / name).write_bytes(data)
            artifacts.append({"name": name, "package": "pkcs11-proxy-ng-shim" if name.endswith(".so")
                              else name, "kind": "lib" if name.endswith(".so") else "bin",
                              "sha256": digest(data), "size": len(data)})
        self.provenance.write_text(json.dumps({"format_version": 1, "source_mode": "archive",
                                               "github_publication_eligible": False,
                                               "source_commit": "a" * 40, "version": "0.2.0",
                                               "target": self.target, "artifacts": artifacts,
                                               "inventory_sha256": "b" * 64,
                                               "tools": {"rustc": "rustc 1.98.1 (fixture)",
                                                         "cargo": "cargo 1.98.1 (fixture)"}}))
        (self.notices / "THIRD_PARTY_NOTICES").write_text("Example upstream license\n")
        (self.notices / "license-material").mkdir()
        (self.notices / "license-material/example-LICENSE").write_text("Permission\n")
        rust_notice = self.notices / "license-material/rust-std/COPYRIGHT-library.html"
        rust_notice.parent.mkdir(parents=True)
        rust_notice.write_text("<html>Rust standard library notice</html>\n")
        own = self.notices / "license-material/pkcs11-proxy-ng-0.2.0/licenses"
        own.mkdir(parents=True)
        for name in ("LICENSE-APACHE", "LICENSE-MIT"):
            (own / name).write_text(name + "\n")
        files = {p.relative_to(self.notices).as_posix(): digest(p.read_bytes())
                 for p in self.notices.rglob("*") if p.is_file()}
        self.inventory.write_text(json.dumps({"format_version": 1, "source_mode": "archive",
                                              "source_commit": "a" * 40, "target": self.target,
                                              "source_inventory_sha256": "b" * 64,
                                              "build_provenance_sha256": digest(self.provenance.read_bytes()),
                                              "artifacts": artifacts, "files": files,
                                              "rust_std": {"version": "rustc 1.98.1 (fixture)",
                                                           "material": "license-material/rust-std/COPYRIGHT-library.html",
                                                           "sha256": files["license-material/rust-std/COPYRIGHT-library.html"]}}))
        for name in ("LICENSE-APACHE", "LICENSE-MIT", "README.md", "CHANGELOG.md"):
            (self.base / name).write_text(name + "\n")
        (self.base / "doc/release").mkdir(parents=True)
        for name in ("beta-support-matrix.md", "mtls-setup.md", "parity-validation.md",
                     "v0.2.0-release-notes.md"):
            (self.base / "doc/release" / name).write_text(name + "\n")

    def test_linux_tar_carries_exact_inputs_and_rejects_stale_notices(self):
        archive = stage_bundle(self.base, self.binaries, self.provenance,
                               self.notices, self.output, timestamp=1_700_000_000)
        with tarfile.open(archive, "r:gz") as bundle:
            names = {member.name.split("/", 1)[1] for member in bundle if member.isfile()}
            self.assertTrue({"bin/pkcs11-proxy-ng", "bin/pkcs11-proxy-ng-cli",
                             "lib/pkcs11/libpkcs11_proxy_ng_shim.so", "LICENSE-MIT",
                             "LICENSE-APACHE", "THIRD_PARTY_NOTICES", "notice-inventory.json",
                             "build-provenance.json", "license-material/example-LICENSE"} <= names)
        (self.notices / "THIRD_PARTY_NOTICES").write_text("changed\n")
        with self.assertRaises(ReleaseError):
            stage_bundle(self.base, self.binaries, self.provenance,
                         self.notices, self.base / "again", timestamp=1_700_000_000)

    def test_stale_target_and_toolchain_cannot_stage(self):
        provenance = json.loads(self.provenance.read_text())
        inventory = json.loads(self.inventory.read_text())
        provenance["target"] = "x86_64-pc-windows-msvc"
        self.provenance.write_text(json.dumps(provenance))
        inventory["build_provenance_sha256"] = digest(self.provenance.read_bytes())
        self.inventory.write_text(json.dumps(inventory))
        with self.assertRaises(ReleaseError):
            stage_bundle(self.base, self.binaries, self.provenance,
                         self.notices, self.output, timestamp=1_700_000_000)
        provenance["target"] = self.target
        provenance["tools"]["rustc"] = "rustc 1.99.0 (wrong)"
        self.provenance.write_text(json.dumps(provenance))
        inventory["build_provenance_sha256"] = digest(self.provenance.read_bytes())
        inventory["rust_std"]["version"] = provenance["tools"]["rustc"]
        self.inventory.write_text(json.dumps(inventory))
        with self.assertRaises(ReleaseError):
            stage_bundle(self.base, self.binaries, self.provenance,
                         self.notices, self.output, timestamp=1_700_000_000)

    def test_missing_version_notes_refuse_with_exact_name(self):
        (self.base / "doc/release/v0.2.0-release-notes.md").unlink()
        with self.assertRaisesRegex(ReleaseError, "release notes for version 0\\.2\\.0"):
            stage_bundle(self.base, self.binaries, self.provenance,
                         self.notices, self.output, timestamp=1_700_000_000)

    def test_later_version_binds_exact_notes(self):
        provenance = json.loads(self.provenance.read_text())
        provenance["version"] = "9.9.9"
        self.provenance.write_text(json.dumps(provenance))
        own = self.notices / "license-material/pkcs11-proxy-ng-9.9.9/licenses"
        own.mkdir(parents=True)
        for name in ("LICENSE-APACHE", "LICENSE-MIT"):
            (own / name).write_text(name + "\n")
        inventory = json.loads(self.inventory.read_text())
        inventory["build_provenance_sha256"] = digest(self.provenance.read_bytes())
        inventory["files"] = {p.relative_to(self.notices).as_posix(): digest(p.read_bytes())
                              for p in self.notices.rglob("*")
                              if p.is_file() and p.name != "notice-inventory.json"}
        self.inventory.write_text(json.dumps(inventory))
        (self.base / "doc/release/v9.9.9-release-notes.md").write_text("later notes\n")
        archive = stage_bundle(self.base, self.binaries, self.provenance,
                               self.notices, self.base / "out9", timestamp=1_700_000_000)
        with tarfile.open(archive, "r:gz") as bundle:
            names = {member.name.split("/", 1)[1] for member in bundle if member.isfile()}
        self.assertIn("doc/v9.9.9-release-notes.md", names)
        self.assertNotIn("doc/v0.2.0-release-notes.md", names)


class PackageCarriageTests(unittest.TestCase):
    def test_apkbuild_maintainer_metadata_is_valid_or_absent(self):
        apkbuild = (ROOT / "packaging/alpine/APKBUILD").read_text()
        # Alpine 3.23 abuild check_maintainer warns but accepts no comment;
        # a machine-readable Maintainer comment must be RFC822 instead.
        # The project uses the approved personal maintainer address.
        matches = re.findall(r"^# *Maintainer[^\n]*", apkbuild, re.M)
        self.assertEqual(len(matches), 1)
        self.assertRegex(matches[0], r"^# *Maintainer: [^<>\n]+ <[^@<>\n ]+@[^@<>\n ]+\.[^@<>\n ]+>$")
        self.assertIn("Denis Mingulov <denis@mingulov.com>", apkbuild)

    def test_spec_changelog_names_approved_maintainer(self):
        spec = (ROOT / "packaging/amazon/pkcs11-proxy-ng.spec").read_text()
        self.assertIn("Denis Mingulov <denis@mingulov.com>", spec)

    def test_alpine_build_user_owns_rustup_and_cargo_homes(self):
        docker = (ROOT / "packaging/alpine/Dockerfile.alpine").read_text()
        builder = docker.split("FROM ${ALPINE_BUILD_IMAGE} AS buildapk", 1)[1].split("USER build", 1)[0]
        self.assertIn("chown -R build:abuild /usr/local/cargo /usr/local/rustup", builder)
        self.assertNotIn("chmod -R a+rwX /usr/local/cargo", builder)
        self.assertNotIn("chmod -R a+rwX /usr/local/rustup", builder)

    def test_apk_functions_install_readable_material_in_each_code_package(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            for relative in ("target/release/pkcs11-proxy-ng",
                             "target/release/pkcs11-proxy-ng-cli",
                             "target/release/libpkcs11_proxy_ng_shim.so",
                             "packaging/config/proxy.toml.default",
                             "packaging/config/mechanism_params.cloudhsm.toml.example",
                             "packaging/alpine/pkcs11-proxy-ng-daemon.openrc",
                             "crates/types/src/mechanism_params_default.toml"):
                path = base / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(relative + "\n")
            for name in ("LICENSE-APACHE", "LICENSE-MIT"):
                (base / name).write_text(name + "\n")
            notices = base / "target/package-notices"
            (notices / "license-material/ring-0.17.14/licenses").mkdir(parents=True)
            (notices / "THIRD_PARTY_NOTICES").write_text("ring 0.17.14\n")
            (notices / "notice-inventory.json").write_text('{"format_version":1}\n')
            (notices / "license-material/ring-0.17.14/licenses/LICENSE").write_text("ISC\n")
            inputs = base / "target/package-notice-inputs"
            inputs.mkdir()
            (inputs / "build-provenance.json").write_text('{"source_mode":"workspace"}\n')
            script = ROOT / "packaging/alpine/APKBUILD"
            shell = (
                'startdir="$1"; source "$2"; builddir="$1"; '
                'for part in shim daemon cli compat; do '
                'subpkgdir="$1/out/$part"; mkdir -p "$subpkgdir"; "$part"; '
                'if [ "$part" = compat ]; then printf "%s" "$depends" > "$1/compat-dep"; fi; '
                'done'
            )
            result = subprocess.run(["bash", "-euc", shell, "bash", str(base), str(script)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            for part in ("shim", "daemon", "cli"):
                folder = base / "out" / part / "usr/share/licenses" / f"pkcs11-proxy-ng-{part}"
                for relative in ("LICENSE-APACHE", "LICENSE-MIT", "THIRD_PARTY_NOTICES",
                                 "notice-inventory.json", "build-provenance.json",
                                 "license-material/ring-0.17.14/licenses/LICENSE"):
                    with self.subTest(part=part, relative=relative):
                        self.assertTrue((folder / relative).is_file(), str(folder / relative))
                        self.assertTrue((folder / relative).read_bytes().strip())
            self.assertEqual((base / "compat-dep").read_text(),
                             "pkcs11-proxy-ng-shim=0.2.0-r0")
            self.assertFalse((base / "out/compat/usr/share/licenses").exists())

    def test_rpm_build_and_code_file_lists_carry_notices(self):
        spec = (ROOT / "packaging/amazon/pkcs11-proxy-ng.spec").read_text()
        docker = (ROOT / "packaging/amazon/Dockerfile.amazon").read_text()
        build = spec.split("\n%build\n", 1)[1].split("\n%install\n", 1)[0]
        self.assertIn("cargo build --release --workspace --locked", build)
        self.assertIn("python3.11 scripts/release_checks.py workspace-notices", build)
        self.assertIn("python3.11", docker)
        self.assertIn("Cargo.toml Cargo.lock", docker)
        self.assertIn("scripts packaging crates", docker)
        self.assertNotIn("cp -a Cargo.toml Cargo.lock README.md CHANGELOG.md", docker)
        smoke = docker.split("FROM ${AMAZON_BUILD_IMAGE} AS buildtest", 1)[1]
        for name in ("LICENSE-APACHE", "LICENSE-MIT", "THIRD_PARTY_NOTICES",
                     "notice-inventory.json", "build-provenance.json",
                     "license-material/ring-0.17.14/licenses/LICENSE",
                     "license-material/rust-std/COPYRIGHT-library.html"):
            self.assertIn(name, smoke)
        self.assertIn('for pkg in pkcs11-proxy-ng-shim pkcs11-proxy-ng-daemon pkcs11-proxy-ng-cli;', smoke)
        for part in ("shim", "daemon", "cli"):
            section = spec.split(f"\n%files {part}\n", 1)[1].split("\n%files", 1)[0]
            for name in ("LICENSE-APACHE", "LICENSE-MIT", "THIRD_PARTY_NOTICES",
                         "license-material", "notice-inventory.json", "build-provenance.json"):
                with self.subTest(part=part, name=name):
                    self.assertRegex(section, r"%license[^\n]*" + re.escape(name))
        self.assertIn("Requires:       %{name}-shim = %{version}-%{release}", spec)

    def test_apk_build_can_regenerate_only_its_owned_notice_outputs(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            (base / "target").mkdir()
            (base / "packaging/alpine").mkdir(parents=True)
            (base / "target/keep-me").write_text("unrelated\n")
            script = ROOT / "packaging/alpine/APKBUILD"
            shell = r'''
                startdir="$1/packaging/alpine"; builddir="$1"; source "$2"
                cargo() { :; }
                rustc() { printf 'host: x86_64-unknown-linux-musl\n'; }
                python3() {
                    local previous="" inputs="" output=""
                    for arg in "$@"; do
                        case "$previous" in
                            --inputs-output) inputs="$arg" ;;
                            --output) output="$arg" ;;
                        esac
                        previous="$arg"
                    done
                    test ! -e "$inputs" && test ! -e "$output" || return 41
                    mkdir -p "$inputs" "$output"
                    printf 'generated\n' > "$output/THIRD_PARTY_NOTICES"
                }
                build
                printf 'stale\n' > "$builddir/target/package-notices/stale"
                build
                test ! -e "$builddir/target/package-notices/stale"
                test -s "$builddir/target/package-notices/THIRD_PARTY_NOTICES"
                test -s "$builddir/target/keep-me"
            '''
            result = subprocess.run(["bash", "-euc", shell, "bash", str(base), str(script)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


class WindowsBundleTests(unittest.TestCase):
    setUp = BundleTests.setUp

    def test_windows_zip_carries_all_material_and_rejects_wrong_binary(self):
        self.target = "x86_64-pc-windows-msvc"
        windows_names = ("pkcs11-proxy-ng.exe", "pkcs11-proxy-ng-cli.exe",
                         "pkcs11_proxy_ng_shim.dll", "cross_width_smoke.exe")
        for path in self.binaries.iterdir():
            path.unlink()
        artifacts = []
        for name in windows_names:
            data = ("binary:" + name).encode()
            (self.binaries / name).write_bytes(data)
            artifacts.append({"name": name, "package": "pkcs11-proxy-ng-shim" if "shim" in name or
                              "smoke" in name else name.removesuffix(".exe"),
                              "kind": "lib" if name.endswith(".dll") else
                              "example" if "smoke" in name else "bin",
                              "sha256": digest(data), "size": len(data)})
        provenance = json.loads(self.provenance.read_text())
        provenance.update(target=self.target, artifacts=artifacts)
        self.provenance.write_text(json.dumps(provenance))
        inventory = json.loads(self.inventory.read_text())
        inventory.update(target=self.target, artifacts=artifacts,
                         build_provenance_sha256=digest(self.provenance.read_bytes()))
        self.inventory.write_text(json.dumps(inventory))
        (self.base / "packaging/windows").mkdir(parents=True)
        (self.base / "packaging/windows/proxy.toml.template").write_text("config\n")
        (self.base / "packaging/windows/Run-Pkcs11ProxyNg.ps1").write_text("runner\n")
        archive = stage_bundle(self.base, self.binaries, self.provenance,
                               self.notices, self.output, timestamp=1_700_000_000)
        with zipfile.ZipFile(archive) as bundle:
            names = {name.split("/", 1)[1] for name in bundle.namelist()}
            self.assertTrue({"bin/cross_width_smoke.exe", "lib/pkcs11_proxy_ng_shim.dll",
                             "THIRD_PARTY_NOTICES", "notice-inventory.json",
                             "build-provenance.json", "license-material/example-LICENSE"} <= names)
        (self.binaries / "cross_width_smoke.exe").write_bytes(b"changed")
        with self.assertRaises(ReleaseError):
            stage_bundle(self.base, self.binaries, self.provenance,
                         self.notices, self.base / "again", timestamp=1_700_000_000)


class MacBundleTests(unittest.TestCase):
    setUp = BundleTests.setUp

    def _stage_darwin(self):
        self.target = "aarch64-apple-darwin"
        darwin_names = ("pkcs11-proxy-ng", "pkcs11-proxy-ng-cli",
                        "libpkcs11_proxy_ng_shim.dylib")
        for path in self.binaries.iterdir():
            path.unlink()
        artifacts = []
        for name in darwin_names:
            data = ("binary:" + name).encode()
            (self.binaries / name).write_bytes(data)
            artifacts.append({"name": name, "package": "pkcs11-proxy-ng-shim" if name.endswith(".dylib")
                              else name, "kind": "lib" if name.endswith(".dylib") else "bin",
                              "sha256": digest(data), "size": len(data)})
        provenance = json.loads(self.provenance.read_text())
        provenance.update(target=self.target, artifacts=artifacts)
        self.provenance.write_text(json.dumps(provenance))
        inventory = json.loads(self.inventory.read_text())
        inventory.update(target=self.target, artifacts=artifacts,
                         build_provenance_sha256=digest(self.provenance.read_bytes()))
        self.inventory.write_text(json.dumps(inventory))
        (self.base / "doc/release/macos-install.md").write_text("macos install\n")

    def test_darwin_tar_carries_dylib_and_mac_install_doc(self):
        self._stage_darwin()
        archive = stage_bundle(self.base, self.binaries, self.provenance,
                               self.notices, self.output, timestamp=1_700_000_000)
        self.assertTrue(str(archive).endswith(".tar.gz"))
        with tarfile.open(archive, "r:gz") as bundle:
            names = {member.name.split("/", 1)[1] for member in bundle if member.isfile()}
            self.assertTrue({"bin/pkcs11-proxy-ng", "bin/pkcs11-proxy-ng-cli",
                             "lib/pkcs11/libpkcs11_proxy_ng_shim.dylib", "doc/macos-install.md",
                             "doc/v0.2.0-release-notes.md", "THIRD_PARTY_NOTICES",
                             "notice-inventory.json", "build-provenance.json"} <= names)
        (self.binaries / "libpkcs11_proxy_ng_shim.dylib").write_bytes(b"changed")
        with self.assertRaises(ReleaseError):
            stage_bundle(self.base, self.binaries, self.provenance,
                         self.notices, self.base / "again", timestamp=1_700_000_000)

    def test_missing_mac_install_doc_refuses(self):
        self._stage_darwin()
        (self.base / "doc/release/macos-install.md").unlink()
        with self.assertRaisesRegex(ReleaseError, "macos-install"):
            stage_bundle(self.base, self.binaries, self.provenance,
                         self.notices, self.output, timestamp=1_700_000_000)


if __name__ == "__main__":
    unittest.main()
