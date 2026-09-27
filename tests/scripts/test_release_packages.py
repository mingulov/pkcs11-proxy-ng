"""Behavior checks for the standalone release archive validator."""

import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from release.package_archives import extract_verified_archives, inspect_archives  # noqa: E402
from release.package_model import PACKAGES, ReleaseError, checked_workspace  # noqa: E402
import release_checks  # noqa: E402

EDGES = {
    "types": (), "audit": (), "proto": ("types",),
    "client": ("types", "proto"), "backend": ("types", "proto"),
    "server": ("types", "proto", "backend", "audit"),
    "shim": ("types", "client", "proto"), "cli": ("types", "client", "audit"),
}


def crate_name(directory):
    return "pkcs11-proxy-ng" if directory == "server" else "pkcs11-proxy-ng-" + directory


def git(root, *args):
    return subprocess.check_output(["git", *args], cwd=root, text=True).strip()


class ArchiveFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        (self.repo / "LICENSE-APACHE").write_bytes(b"apache\n")
        (self.repo / "LICENSE-MIT").write_bytes(b"mit\n")
        members = ", ".join(f'"crates/{directory}"' for _, directory in PACKAGES)
        (self.repo / "Cargo.toml").write_text(
            f'[workspace]\nresolver = "2"\nmembers = [{members}]\n'
            '[workspace.package]\nversion = "0.2.0"\nedition = "2024"\n'
            'rust-version = "1.88"\nlicense = "Apache-2.0 OR MIT"\n'
            'repository = "https://example.invalid/proxy"\n'
            '[workspace.dependencies]\nserde = { version = "1", features = ["derive"] }\n'
        )
        (self.repo / "Cargo.lock").write_text(
            'version = 4\n[[package]]\nname = "serde"\nversion = "1.0.0"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            'checksum = "' + "a" * 64 + '"\n'
        )
        for name, directory in PACKAGES:
            root = self.repo / "crates" / directory
            (root / "src").mkdir(parents=True)
            (root / "src" / "lib.rs").write_text("pub fn example() {}\n")
            (root / "README.md").write_text("example\n")
            for license_name in ("LICENSE-APACHE", "LICENSE-MIT"):
                (root / license_name).write_bytes((self.repo / license_name).read_bytes())
            internal = "".join(f'{crate_name(dep)} = {{ version = "=0.2.0", path = "../{dep}" }}\n'
                               for dep in EDGES[directory])
            extra = ('[dependencies]\nserde = { workspace = true, features = ["std"] }\n' + internal +
                     '[dev-dependencies]\n' +
                     ('pkcs11-proxy-ng-types = { path = "../types" }\n' if directory == "client" else '') +
                     'tempfile = "3"\n' +
                     ('[target.\'cfg(unix)\'.dependencies]\nserde_json = "1"\n' if directory == "types" else ''))
            (root / "Cargo.toml").write_text(
                '[package]\n' + f'name = "{name}"\n' +
                'version.workspace = true\nedition.workspace = true\n'
                'rust-version.workspace = true\nlicense.workspace = true\n'
                'repository.workspace = true\npublish = ["crates-io"]\n'
                'description = "fixture"\nreadme = "README.md"\n'
                'include = ["Cargo.toml", "README.md", "LICENSE-APACHE", '
                '"LICENSE-MIT", "src/**"]\n' + extra
            )
        git(self.repo, "init", "-q")
        git(self.repo, "add", ".")
        subprocess.check_call(["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                               "commit", "-qm", "fixture"], cwd=self.repo)
        self.head = git(self.repo, "rev-parse", "HEAD")
        self.packages = Path(self.temp.name) / "packages"
        self.packages.mkdir()
        self.build_all()

    def normalized(self, name, directory):
        return (
            '[package]\n' + f'name = "{name}"\nversion = "0.2.0"\n'
            'edition = "2024"\nrust-version = "1.88"\n'
            'license = "Apache-2.0 OR MIT"\nrepository = "https://example.invalid/proxy"\n'
            'publish = ["crates-io"]\ndescription = "fixture"\nreadme = "README.md"\n'
            'include = ["Cargo.toml", "README.md", "LICENSE-APACHE", '
            '"LICENSE-MIT", "src/**"]\nbuild = false\n'
            'autolib = false\nautobins = false\nautoexamples = false\n'
            'autotests = false\nautobenches = false\nresolver = "2"\n'
            '[lib]\n' + f'name = "{name.replace("-", "_")}"\npath = "src/lib.rs"\n'
            '[dependencies.serde]\nversion = "1"\nfeatures = ["derive", "std"]\n' +
            "".join(f'[dependencies.{crate_name(dep)}]\nversion = "=0.2.0"\n'
                    for dep in EDGES[directory]) +
            '[dev-dependencies.tempfile]\nversion = "3"\n' +
            ('[target.\'cfg(unix)\'.dependencies.serde_json]\nversion = "1"\n'
             if directory == "types" else '')
        ).encode()

    def entries(self, name, directory):
        root = self.repo / "crates" / directory
        entries = {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}
        entries["Cargo.toml.orig"] = entries.pop("Cargo.toml")
        entries["Cargo.toml"] = self.normalized(name, directory)
        entries["Cargo.lock"] = (
            'version = 4\n[[package]]\nname = "serde"\nversion = "1.0.0"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            'checksum = "' + "a" * 64 + '"\n'
        ).encode()
        entries[".cargo_vcs_info.json"] = json.dumps({"git": {"sha1": self.head},
                                                        "path_in_vcs": f"crates/{directory}"}).encode()
        return entries

    def archive(self, name, directory, *, entries=None, additional=()):
        target = self.packages / f"{name}-0.2.0.crate"
        with tarfile.open(target, "w:gz") as out:
            for relative, content in (entries or self.entries(name, directory)).items():
                info = tarfile.TarInfo(f"{name}-0.2.0/{relative}")
                info.size = len(content)
                out.addfile(info, io.BytesIO(content))
            for info, content in additional:
                out.addfile(info, io.BytesIO(content) if content is not None else None)
        return target

    def build_all(self):
        for name, directory in PACKAGES:
            self.archive(name, directory)

    def mutate(self, relative, change, name=PACKAGES[0][0], directory=PACKAGES[0][1]):
        entries = self.entries(name, directory)
        entries[relative] = change(entries[relative])
        self.archive(name, directory, entries=entries)

    def assert_refused(self):
        with self.assertRaises(ReleaseError):
            inspect_archives(self.repo, self.packages)


class ReleasePackageTests(ArchiveFixture):
    def test_inventory_and_safe_extraction(self):
        inventory = inspect_archives(self.repo, self.packages, write=True)
        self.assertEqual(inventory["source_commit"], self.head)
        self.assertEqual(inventory["format_version"], 1)
        self.assertEqual(len(inventory["packages"]), 8)
        self.assertEqual(len((self.packages / "SHA256SUMS").read_text().splitlines()), 8)
        self.assertEqual(json.loads((self.packages / "inventory.json").read_text()), inventory)
        dest = Path(self.temp.name) / "extracted"
        roots = extract_verified_archives(self.repo, self.packages, dest)
        self.assertEqual((roots["pkcs11-proxy-ng-types"] / "src/lib.rs").read_text(),
                         "pub fn example() {}\n")
        with self.assertRaises(ReleaseError):
            extract_verified_archives(self.repo, self.packages, dest)

    def test_refuses_missing_extra_and_changed_archive(self):
        archive = self.packages / "pkcs11-proxy-ng-audit-0.2.0.crate"
        archive.unlink()
        self.assert_refused()
        self.archive(*PACKAGES[0])
        (self.packages / "surprise.crate").write_bytes(b"x")
        self.assert_refused()
        (self.packages / "surprise.crate").unlink()
        self.mutate("src/lib.rs", lambda _: b"altered")
        self.assert_refused()
        name, directory = PACKAGES[0]
        entries = self.entries(name, directory)
        del entries["README.md"]
        self.archive(name, directory, entries=entries)
        self.assert_refused()

    def test_refuses_unsafe_members(self):
        name, directory = PACKAGES[0]
        for path in ("../escape", "/absolute", "src\\bad", "src/../bad", "src/.private",
                     "src//bad", "src/bad/"):
            with self.subTest(path=path):
                info = tarfile.TarInfo(f"{name}-0.2.0/{path}")
                info.size = 1
                self.archive(name, directory, additional=((info, b"x"),))
                self.assert_refused()
        relative = f"{name}-0.2.0/src/lib.rs"
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE):
            with self.subTest(kind=kind):
                info = tarfile.TarInfo(relative)
                info.type = kind
                info.linkname = "../outside"
                self.archive(name, directory, additional=((info, None),))
                self.assert_refused()
        info = tarfile.TarInfo(relative)
        info.size = 1
        self.archive(name, directory, additional=((info, b"x"),))
        self.assert_refused()

    def test_refuses_oversized_header_and_many_directories(self):
        name, directory = PACKAGES[0]
        info = tarfile.TarInfo(f"{name}-0.2.0/src/too-large")
        info.size = 16 * 1024 * 1024 + 1
        self.archive(name, directory, additional=((info, b"x" * info.size),))
        self.assert_refused()
        many = []
        for index in range(1001):
            directory_info = tarfile.TarInfo(f"{name}-0.2.0/src/d{index}/")
            directory_info.type = tarfile.DIRTYPE
            many.append((directory_info, None))
        self.archive(name, directory, additional=many)
        self.assert_refused()
        files = []
        for index in range(1001):
            file_info = tarfile.TarInfo(f"{name}-0.2.0/src/f{index}")
            file_info.size = 1
            files.append((file_info, b"x"))
        self.archive(name, directory, additional=files)
        self.assert_refused()
        pax = tarfile.TarInfo(f"{name}-0.2.0/src/pax")
        pax.pax_headers = {"comment": "x" * (17 * 1024)}
        pax.size = 1
        self.archive(name, directory, additional=((pax, b"x"),))
        self.assert_refused()

    def test_refuses_total_unpacked_content_over_limit(self):
        name, directory = PACKAGES[0]
        payload = b"x" * (16 * 1024 * 1024)
        files = []
        for index in range(4):
            info = tarfile.TarInfo(f"{name}-0.2.0/src/big{index}")
            info.size = len(payload)
            files.append((info, payload))
        self.archive(name, directory, additional=files)
        self.assert_refused()

    def test_refuses_gitignored_source_even_when_checkout_is_clean(self):
        ignore = self.repo / ".gitignore"
        ignore.write_text("crates/types/src/ignored.rs\n")
        git(self.repo, "add", ".gitignore")
        subprocess.check_call(["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                               "commit", "-qm", "ignore"], cwd=self.repo)
        self.head = git(self.repo, "rev-parse", "HEAD")
        ignored = self.repo / "crates/types/src/ignored.rs"
        ignored.write_text("pub fn hidden() {}\n")
        self.build_all()
        self.assertEqual(git(self.repo, "status", "--porcelain", "--untracked-files=all"), "")
        self.assert_refused()

    def test_refuses_manifest_and_vcs_mutations(self):
        name, directory = PACKAGES[0]
        cases = (
            ("Cargo.toml", lambda b: b.replace(b'features = ["derive", "std"]', b'features = ["derive"]')),
            ("Cargo.toml", lambda b: b.replace(b'version = "1"', b'version = "2"')),
            ("Cargo.toml", lambda b: b.replace(b"[target.'cfg(unix)'.dependencies.serde_json]\nversion = \"1\"",
                                                b"[target.'cfg(unix)'.dependencies.serde_json]\nversion = \"2\"")),
            ("Cargo.toml", lambda b: b.replace(b'build = false', b'build = "../build.rs"')),
            ("Cargo.toml", lambda b: b.replace(b'edition = "2024"', b'edition = "2021"')),
            ("Cargo.toml", lambda b: b.replace(b'[dev-dependencies.tempfile]', b'[dev-dependencies.bad]')),
            ("Cargo.toml.orig", lambda b: b + b"# changed\n"),
            (".cargo_vcs_info.json", lambda b: b.replace(self.head.encode(), b"0" * 40)),
            (".cargo_vcs_info.json", lambda b: b.replace(b"crates/types", b"../types")),
            (".cargo_vcs_info.json", lambda b: b.replace(b'"git":', b'"dirty": true, "git":')),
        )
        for index, (relative, change) in enumerate(cases):
            with self.subTest(index=index, relative=relative):
                self.mutate(relative, change, name, directory)
                self.assert_refused()
        # Cargo omits path-only cross-project dev dependencies from the archive.
        client, client_dir = PACKAGES[3]
        self.mutate("Cargo.toml", lambda b: b + b'[dev-dependencies.pkcs11-proxy-ng-types]\nversion = "=0.2.0"\n', client, client_dir)
        self.assert_refused()
        self.mutate("Cargo.toml", lambda b: b.replace(b'version = "=0.2.0"', b'version = "=0.3.0"', 1),
                    client, client_dir)
        self.assert_refused()

    def test_refuses_target_and_metadata_drift(self):
        name, directory = PACKAGES[0]
        for old, new in ((b'path = "src/lib.rs"', b'path = "../lib.rs"'),
                         (b'description = "fixture"', b'description = "forged"'),
                         (b'readme = "README.md"', b'readme = "../README.md"'),
                         (b'license = "Apache-2.0 OR MIT"', b'license = "MIT"'),
                         (b'publish = ["crates-io"]', b'publish = ["private"]')):
            with self.subTest(old=old):
                self.mutate("Cargo.toml", lambda b: b.replace(old, new))
                self.assert_refused()

    def test_refuses_unrequested_dependency_identity_fields(self):
        for field in (b'package = "serde_json"', b'registry = "other"',
                      b'registry-index = "https://example.invalid/index"',
                      b'optional = false', b'default-features = true'):
            with self.subTest(field=field):
                self.mutate("Cargo.toml", lambda b: b.replace(
                    b'[dependencies.serde]\n', b'[dependencies.serde]\n' + field + b'\n'))
                self.assert_refused()

    def test_refuses_unrequested_target_field(self):
        self.mutate("Cargo.toml", lambda b: b.replace(
            b'[lib]\n', b'[lib]\ncrate-type = ["rlib"]\n'))
        self.assert_refused()

    def test_refuses_unrequested_package_field(self):
        self.mutate("Cargo.toml", lambda b: b.replace(
            b'readme = "README.md"\n',
            b'readme = "README.md"\nlicense-file = "README.md"\n'))
        self.assert_refused()

    def test_refuses_generated_lockfile_git_source(self):
        self.mutate("Cargo.lock", lambda b: b.replace(
            b"registry+https://github.com/rust-lang/crates.io-index",
            b"git+https://example.invalid/forged"))
        self.assert_refused()

    def test_refuses_generated_lockfile_checksum_drift(self):
        self.mutate("Cargo.lock", lambda b: b.replace(b"a" * 64, b"b" * 64))
        self.assert_refused()

    def test_refuses_generated_internal_archive_checksum_drift(self):
        name, directory = PACKAGES[3]
        forged = (b'[[package]]\nname = "pkcs11-proxy-ng-types"\nversion = "0.2.0"\n'
                  b'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                  b'checksum = "' + b"b" * 64 + b'"\n')
        self.mutate("Cargo.lock", lambda b: b + forged, name, directory)
        self.assert_refused()

    def test_refuses_generated_source_override(self):
        self.mutate("Cargo.toml", lambda b: b + b'[source.crates-io]\nreplace-with = "local"\n')
        self.assert_refused()

    def test_refuses_wrong_expected_inventory_without_overwrite(self):
        inspect_archives(self.repo, self.packages, write=True)
        baseline = self.packages / "inventory.json"
        original = baseline.read_bytes()
        name, directory = PACKAGES[0]
        self.archive(name, directory, entries=dict(reversed(list(self.entries(name, directory).items()))))
        self.assertEqual(release_checks.main(["archives", "--package-dir", str(self.packages),
                                              "--expect-inventory", str(baseline)], repo=self.repo), 1)
        self.assertEqual(baseline.read_bytes(), original)

    def test_workspace_rejects_wrong_package_set_and_version(self):
        self.assertEqual(checked_workspace(self.repo), "0.2.0")
        manifest = self.repo / "crates/audit/Cargo.toml"
        manifest.write_text(manifest.read_text().replace('name = "pkcs11-proxy-ng-audit"', 'name = "surprise"'))
        with self.assertRaises(ReleaseError):
            checked_workspace(self.repo)
        self.assert_refused()

    def test_workspace_refuses_extra_crate_manifest(self):
        extra = self.repo / "crates/extra"
        extra.mkdir()
        (extra / "Cargo.toml").write_text('[package]\nname = "extra"\nversion = "0.2.0"\n')
        with self.assertRaises(ReleaseError):
            checked_workspace(self.repo)


if __name__ == "__main__":
    unittest.main()
