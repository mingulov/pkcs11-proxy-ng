"""Binary-bundle documentation/link contract (RO-04).

The release bundle must be a self-sufficient operator install: the
install guide, complete secure config templates, and the
runbook/error/support material the guide needs ship inside the
archive with repository-relative paths, and every relative link in
every bundled markdown file resolves within the archive. Links to
material deliberately left out of the bundle are rewritten at stage
time to immutable version-pinned online references.
"""

import re
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from release.package_model import ReleaseError  # noqa: E402
from release.package_bundles import stage_bundle  # noqa: E402
import test_release_notices as notices_tests  # noqa: E402

ONLINE_BASE = "https://github.com/mingulov/pkcs11-proxy-ng"


def workspace_version():
    text = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"', text)
    if not match:
        raise AssertionError("workspace version not found in Cargo.toml")
    return match.group(1)


def extract_markdown_links(text):
    """Inline ``[text](target)`` links (images included).

    Returns the raw targets in order. Callers skip absolute URLs and
    pure fragments.
    """
    return re.findall(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)", text)


def is_external(target):
    return "://" in target or target.startswith(("mailto:", "#"))


def check_stage_links(stage):
    """Every relative link in every staged ``.md`` must resolve in-stage.

    Returns the list of dangling ``(file, target)`` pairs (empty when
    the bundle is coherent).
    """
    stage = Path(stage)
    dangling = []
    for path in sorted(stage.rglob("*.md")):
        for target in extract_markdown_links(path.read_text(encoding="utf-8")):
            if is_external(target):
                continue
            bare = target.split("#", 1)[0].strip().strip("<>")
            if not bare:
                continue
            resolved = (path.parent / bare).resolve()
            try:
                resolved.relative_to(stage.resolve())
            except ValueError:
                dangling.append((path.relative_to(stage).as_posix(), target))
                continue
            if not resolved.exists():
                dangling.append((path.relative_to(stage).as_posix(), target))
    return dangling


class BundleMemberTests(notices_tests.BundleTests):
    """The prepared archive carries the install material (fixture)."""

    def setUp(self):
        super().setUp()
        # Fixture docs with the same link shapes as the real bundle
        # inputs: README points into doc/release/, the mTLS guide
        # points at examples/ and the runbook, and the install guide
        # points at the bundle template plus unbundled dev material.
        (self.base / "README.md").write_text(
            "# fixture\n[matrix](./doc/release/beta-support-matrix.md)\n"
            "[dev-guide](./doc/development.md)\n"
        )
        (self.base / "doc/release/mtls-setup.md").write_text(
            "# fixture\n[staging](../../examples/configs/staging/proxy.toml)\n"
            "[runbook](../runbooks/operating-pkcs11-proxy-ng.md)\n"
        )
        (self.base / "doc/release/bundle-install.md").write_text(
            "# fixture\n[config](../../examples/configs/bundle/proxy.toml)\n"
            "[dev-doc](../../doc/development.md)\n"
        )
        (self.base / "doc/runbooks").mkdir(parents=True, exist_ok=True)
        (self.base / "doc/runbooks/operating-pkcs11-proxy-ng.md").write_text(
            "# fixture\n[errors](../error-reference.md)\n"
        )
        (self.base / "doc/error-reference.md").write_text("# fixture\n")
        # Unbundled but present in the repo: links to it must become
        # immutable online references (not dangling local links).
        (self.base / "doc/development.md").write_text("# fixture\n")
        for tier in ("prod", "staging", "bundle"):
            directory = self.base / "examples/configs" / tier
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "proxy.toml").write_text(f"# fixture {tier}\n")

    def stage_and_extract(self):
        archive = stage_bundle(self.base, self.binaries, self.provenance,
                               self.notices, self.output, timestamp=1_700_000_000)
        extracted = Path(self.temp.name) / "extracted"
        with tarfile.open(archive, "r:gz") as bundle:
            bundle.extractall(extracted, filter="data")
        tops = [item for item in extracted.iterdir() if item.is_dir()]
        self.assertEqual(len(tops), 1)
        return archive, tops[0]

    def test_prepared_archive_carries_install_guide_and_templates(self):
        _archive, stage = self.stage_and_extract()
        for member in (
            "INSTALL.md",
            "doc/release/beta-support-matrix.md",
            "doc/release/mtls-setup.md",
            "doc/release/parity-validation.md",
            "doc/release/health-contract.md",
            "doc/release/pool-evidence.json",
            "doc/release/v0.2.0-release-notes.md",
            "doc/runbooks/operating-pkcs11-proxy-ng.md",
            "doc/error-reference.md",
            "examples/configs/prod/proxy.toml",
            "examples/configs/staging/proxy.toml",
            "examples/configs/bundle/proxy.toml",
        ):
            with self.subTest(member=member):
                path = stage / member
                self.assertTrue(path.is_file(), f"bundle lacks {member}")
                self.assertTrue(path.stat().st_size > 0, f"bundle member empty: {member}")
        # The old flattened relocation must be gone: doc/ entries keep
        # their repository-relative paths.
        self.assertFalse((stage / "doc/mtls-setup.md").exists(),
                         "flattened doc/mtls-setup.md must move to doc/release/")
        # The install guide is the top-level entry point.
        self.assertTrue((stage / "INSTALL.md").is_file())

    def test_prepared_archive_links_resolve(self):
        _archive, stage = self.stage_and_extract()
        dangling = check_stage_links(stage)
        self.assertEqual(dangling, [], f"dangling bundle links: {dangling}")

    def test_unbundled_links_rewritten_to_immutable_online_refs(self):
        _archive, stage = self.stage_and_extract()
        readme = (stage / "README.md").read_text(encoding="utf-8")
        self.assertIn(f"{ONLINE_BASE}/blob/v0.2.0/doc/development.md", readme)
        install = (stage / "INSTALL.md").read_text(encoding="utf-8")
        self.assertIn(f"{ONLINE_BASE}/blob/v0.2.0/doc/development.md", install)
        # Bundled targets stay bundle-local (no online rewrite).
        self.assertIn("examples/configs/bundle/proxy.toml", install)
        self.assertNotIn(f"{ONLINE_BASE}/blob/v0.2.0/examples/configs/bundle/proxy.toml",
                         install)
        # Nothing may point at a mutable branch.
        for path in sorted(stage.rglob("*.md")):
            with self.subTest(path=path.relative_to(stage).as_posix()):
                self.assertNotIn("/blob/main/",
                                 path.read_text(encoding="utf-8"))

    def test_missing_install_guide_refuses_with_exact_name(self):
        (self.base / "doc/release/bundle-install.md").unlink()
        with self.assertRaisesRegex(ReleaseError, "bundle-install"):
            stage_bundle(self.base, self.binaries, self.provenance,
                         self.notices, self.base / "again", timestamp=1_700_000_000)


class RealRepoBundleLinkTests(unittest.TestCase):
    """The real staged docs link coherently (prepared-archive layout)."""

    def test_real_staged_docs_links_resolve(self):
        from release.package_bundles import bundle_doc_mapping, repair_bundle_markdown_links
        version = workspace_version()
        mapping = bundle_doc_mapping(ROOT, version)
        self.assertIn("INSTALL.md", mapping)
        with tempfile.TemporaryDirectory() as temp:
            stage = Path(temp) / "stage"
            for staged_rel, source in mapping.items():
                dest = stage / staged_rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(Path(source).read_bytes())
            # The real bundle also carries the top-level licenses (from
            # the notice material); the README links to them.
            for name in ("LICENSE-APACHE", "LICENSE-MIT"):
                (stage / name).write_bytes((ROOT / name).read_bytes())
            report = repair_bundle_markdown_links(stage, mapping, ROOT, version)
            dangling = check_stage_links(stage)
            self.assertEqual(dangling, [], f"dangling bundle links: {dangling}")
            for staged_rel, urls in sorted(report.items()):
                for url in urls:
                    with self.subTest(file=staged_rel, url=url):
                        self.assertIn(f"/v{version}/", url)
                        self.assertTrue("/blob/" in url or "/tree/" in url, url)
                        self.assertNotIn("/blob/main/", url)
                        self.assertNotIn("/tree/main/", url)

    def test_install_guide_notes_link_tracks_workspace_version(self):
        # The install guide ships in the bundle next to exactly one
        # notes file (v{version}-release-notes.md). A stale notes link
        # would be "repaired" into an online pointer at old notes while
        # the current notes sit bundle-local beside the guide.
        from release.package_bundles import bundle_doc_mapping
        version = workspace_version()
        mapping = bundle_doc_mapping(ROOT, version)
        guide = Path(mapping["INSTALL.md"]).read_text(encoding="utf-8")
        self.assertIn(f"(v{version}-release-notes.md)", guide)

    def test_real_bundle_template_members_exist(self):
        from release.package_bundles import bundle_doc_mapping
        mapping = bundle_doc_mapping(ROOT, workspace_version())
        for member in ("examples/configs/prod/proxy.toml",
                       "examples/configs/staging/proxy.toml",
                       "examples/configs/bundle/proxy.toml",
                       "doc/runbooks/operating-pkcs11-proxy-ng.md",
                       "doc/error-reference.md"):
            with self.subTest(member=member):
                self.assertIn(member, mapping)
                self.assertTrue(Path(mapping[member]).is_file(), member)

    def test_online_refs_resolve_at_pinned_tag(self):
        # Beyond URL spelling: every immutable reference the repair
        # produces must name a target that exists at the pinned tag
        # (a same-checkout existence check is not enough — the URL
        # points at v{version}, not at the working tree).
        import shutil
        import subprocess
        from release.package_bundles import bundle_doc_mapping, repair_bundle_markdown_links
        if shutil.which("git") is None:
            self.skipTest("git unavailable")
        version = workspace_version()
        tag = f"v{version}"
        tagged = subprocess.run(["git", "rev-parse", "--verify", tag],
                                cwd=ROOT, capture_output=True)
        # Pre-tag candidates must validate too (the script gate refuses
        # skips): verify the link targets against the candidate tree at
        # HEAD, which is what the tag will freeze. Post-tag the pinned
        # tag itself is authoritative.
        ref = tag if tagged.returncode == 0 else "HEAD"
        mapping = bundle_doc_mapping(ROOT, version)
        with tempfile.TemporaryDirectory() as temp:
            stage = Path(temp) / "stage"
            for staged_rel, source in mapping.items():
                dest = stage / staged_rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(Path(source).read_bytes())
            for name in ("LICENSE-APACHE", "LICENSE-MIT"):
                (stage / name).write_bytes((ROOT / name).read_bytes())
            report = repair_bundle_markdown_links(stage, mapping, ROOT, version)
        missing = []
        for staged_rel, urls in sorted(report.items()):
            for url in urls:
                match = re.match(re.escape(ONLINE_BASE) + r"/(blob|tree)/v([^/]+)/(.+)$",
                                 url)
                self.assertIsNotNone(match, f"unexpected online URL shape: {url}")
                _kind, pinned, target = match.group(1), match.group(2), match.group(3)
                target = target.split("#", 1)[0]
                self.assertEqual(pinned, version, f"URL pins the wrong version: {url}")
                probe = subprocess.run(["git", "cat-file", "-e", f"{ref}:{target}"],
                                       cwd=ROOT, capture_output=True)
                if probe.returncode != 0:
                    missing.append(f"{staged_rel} -> {url}")
        self.assertEqual(missing, [],
                         f"online references missing at {ref}: {missing}")


class RealRepoBundleGuideTests(unittest.TestCase):
    """The shipped install guide is operationally reproducible."""

    def test_guide_provisions_token_store_before_daemon_start(self):
        # The daemon inherits the provider environment at launch; a
        # SOFTHSM2_CONF exported after startup cannot change it. The
        # scratch store must be provisioned before the start command,
        # and the start command must carry the same configuration.
        guide = (ROOT / "doc/release/bundle-install.md").read_text(encoding="utf-8")
        provision = guide.find("directories.tokendir")
        start = guide.find("./bin/pkcs11-proxy-ng proxy.toml")
        self.assertNotEqual(provision, -1, "guide must provision a scratch token store")
        self.assertNotEqual(start, -1, "guide must give the daemon start command")
        self.assertLess(provision, start,
                        "scratch provisioning must precede the daemon start")
        start_block = guide[max(0, guide.rfind("```bash", 0, start)):start]
        self.assertIn("SOFTHSM2_CONF", start_block,
                      "the daemon launch must carry the scratch configuration")

    def test_guide_selects_platform_correct_shim(self):
        # The guide targets Linux and macOS tarballs, which ship
        # different shim names (.so vs .dylib). Consumer commands
        # must select the shim per platform, never hardcode one.
        guide = (ROOT / "doc/release/bundle-install.md").read_text(encoding="utf-8")
        self.assertIn("libpkcs11_proxy_ng_shim.so", guide)
        self.assertIn("libpkcs11_proxy_ng_shim.dylib", guide)
        offenders = [line.strip() for line in guide.splitlines()
                     if "--module" in line and "libpkcs11_proxy_ng_shim.so" in line]
        self.assertEqual(offenders, [],
                         f"consumer commands hardcode the Linux shim: {offenders}")

    def test_readme_bundle_route_names_per_platform_entry(self):
        # Every bundle operator is routed by the README: Unix
        # archives carry INSTALL.md, while the Windows ZIP carries
        # the config template plus the supervisor script instead.
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        pointer = [paragraph for paragraph in readme.split("\n\n")
                   if "Installed from a release bundle" in paragraph]
        self.assertEqual(len(pointer), 1, "README must route bundle operators once")
        text = pointer[0]
        self.assertIn("INSTALL.md", text)
        self.assertIn("proxy.toml.template", text,
                      "the bundle route must name the Windows entry point")


class BundleTargetEntryTests(unittest.TestCase):
    """Each archive's advertised entry point and artifact paths."""

    def test_each_target_entry_point_and_artifacts(self):
        from release.package_bundles import _bundle_files, bundle_doc_mapping
        from release.package_binaries import TARGETS
        repo = ROOT
        with tempfile.TemporaryDirectory() as temp:
            tmp = Path(temp)
            binaries = tmp / "binaries"
            binaries.mkdir()
            notices = tmp / "notices"
            notices.mkdir()
            provenance = tmp / "build-provenance.json"
            provenance.write_text("{}\n")
            linux, windows, macos = TARGETS
            unix_docs = bundle_doc_mapping(repo, workspace_version(), linux)
            self.assertIn("INSTALL.md", unix_docs,
                          "Linux bundle entry point must be INSTALL.md")
            mac_docs = bundle_doc_mapping(repo, workspace_version(), macos)
            self.assertIn("INSTALL.md", mac_docs)
            self.assertIn("doc/release/macos-install.md", mac_docs)
            win_docs = bundle_doc_mapping(repo, workspace_version(), windows)
            self.assertNotIn("INSTALL.md", win_docs,
                             "Windows ZIP carries no INSTALL.md")
            win_files = _bundle_files(repo, binaries, provenance, notices,
                                      windows, workspace_version())
            for member in ("proxy.toml.template", "Run-Pkcs11ProxyNg.ps1"):
                with self.subTest(member=member):
                    self.assertIn(member, win_files)
                    self.assertTrue(Path(win_files[member]).is_file(), member)
            for member in ("bin/pkcs11-proxy-ng.exe", "bin/pkcs11-proxy-ng-cli.exe",
                           "bin/cross_width_smoke.exe",
                           "lib/pkcs11_proxy_ng_shim.dll"):
                with self.subTest(member=member):
                    self.assertIn(member, win_files,
                                  "Windows artifact path must be staged")
            linux_files = _bundle_files(repo, binaries, provenance, notices,
                                        linux, workspace_version())
            self.assertIn("lib/pkcs11/libpkcs11_proxy_ng_shim.so", linux_files)
            mac_files = _bundle_files(repo, binaries, provenance, notices,
                                      macos, workspace_version())
            self.assertIn("lib/pkcs11/libpkcs11_proxy_ng_shim.dylib", mac_files)


if __name__ == "__main__":
    unittest.main()
