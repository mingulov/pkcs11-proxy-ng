"""Release ref and qualification refusal cases against real Git histories."""

import io
import json
from contextlib import redirect_stderr
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from release.package_model import PACKAGES  # noqa: E402
import release_checks  # noqa: E402

EDGES = {
    "types": (), "audit": (), "proto": ("types",),
    "client": ("types", "proto"), "backend": ("types", "proto"),
    "server": ("types", "proto", "backend", "audit"),
    "shim": ("types", "client", "proto"), "cli": ("types", "client", "audit"),
}


def git(repo, *args):
    result = subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True)
    if result.returncode:
        raise AssertionError(result.stderr)
    return result.stdout.strip()


class RefFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "config", "user.name", "Fixture")
        git(self.repo, "config", "user.email", "fixture@example.invalid")
        members = ", ".join(f'"crates/{directory}"' for _, directory in PACKAGES)
        (self.repo / "Cargo.toml").write_text(
            f'[workspace]\nmembers = [{members}]\n'
            '[workspace.package]\nversion = "0.2.0"\n'
        )
        for name, directory in PACKAGES:
            crate = self.repo / "crates" / directory
            crate.mkdir(parents=True)
            dependencies = "".join(
                f'{next(n for n, d in PACKAGES if d == dependency)} = '
                f'{{ version = "=0.2.0", path = "../{dependency}" }}\n'
                for dependency in EDGES[directory]
            )
            (crate / "Cargo.toml").write_text(
                f'[package]\nname = "{name}"\nversion.workspace = true\n'
                'publish = ["crates-io"]\n'
                'include = ["Cargo.toml", "README.md", "LICENSE-APACHE", '
                '"LICENSE-MIT", "src/**"]\n'
                f'[dependencies]\n{dependencies}'
            )
        (self.repo / "source.txt").write_text("source\n")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-qm", "subject")
        self.subject = git(self.repo, "rev-parse", "HEAD")
        receipt = self.repo / "doc/release/v0.2.0-quality-receipt.md"
        receipt.parent.mkdir(parents=True)
        receipt.write_text("subject_sha: " + self.subject + "\n" + "".join(
            gate + ": pass\n" for gate in
            ("fmt", "check", "test", "clippy", "msrv", "audit", "deny", "release_dry_run")
        ))
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-qm", "receipt")
        self.head = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "tag", "-a", "v0.2.0", "-m", "release")
        git(self.repo, "update-ref", "refs/remotes/origin/main", self.head)

    def check(self, *args):
        return release_checks.main(["preflight", "--ref", "refs/tags/v0.2.0",
                                    "--require-main", *args], repo=self.repo)

    def test_accepts_annotated_clean_main_tag_and_upload_qualification(self):
        self.assertEqual(self.check(), 0)
        self.assertEqual(self.check("--mode", "trusted", "--package", PACKAGES[0][0],
                                    "--qualification-subject", self.subject,
                                    "--qualification-url", "https://example.invalid/qualification"), 0)
        self.assertEqual(self.check("--mode", "bootstrap", "--qualification-subject", self.subject,
                                    "--qualification-url", "https://example.invalid/qualification"), 0)

    def test_rejects_bad_refs_and_tag_topologies(self):
        for ref in ("v0.2.0", "refs/heads/main", "refs/tags/v0.2.0-rc1",
                    "refs/tags/v01.2.0", "refs/tags/v0.2.0; true"):
            with self.subTest(ref=ref):
                self.assertEqual(release_checks.main(["preflight", "--ref", ref,
                                                      "--require-main"], repo=self.repo), 1)
        git(self.repo, "tag", "-f", "v0.2.0", self.head)
        self.assertEqual(self.check(), 1)  # lightweight
        git(self.repo, "tag", "-fa", "v0.2.0", self.subject, "-m", "wrong target")
        self.assertEqual(self.check(), 1)
        git(self.repo, "tag", "-fa", "v0.2.0", self.head, "-m", "release")
        git(self.repo, "update-ref", "refs/remotes/origin/main", self.subject)
        self.assertEqual(self.check(), 1)

    def test_rejects_tag_object_with_different_embedded_name(self):
        git(self.repo, "tag", "-a", "v0.3.0", "-m", "other name")
        other_tag = git(self.repo, "rev-parse", "refs/tags/v0.3.0")
        git(self.repo, "update-ref", "refs/tags/v0.2.0", other_tag)
        self.assertEqual(self.check(), 1)

    def test_rejects_version_and_dirty_tree(self):
        manifest = self.repo / "Cargo.toml"
        manifest.write_text(manifest.read_text().replace('0.2.0', '0.3.0'))
        self.assertEqual(self.check(), 1)
        git(self.repo, "restore", "Cargo.toml")
        # A tracked modification that keeps the manifest contract valid
        # must trip the clean-tree guard specifically — not an earlier
        # guard that happens to fire first.
        (self.repo / "source.txt").write_text("source\nmodified\n")
        buffer = io.StringIO()
        with redirect_stderr(buffer):
            self.assertEqual(self.check(), 1)
        self.assertIn("must be clean", buffer.getvalue())
        git(self.repo, "restore", "source.txt")
        (self.repo / "untracked").write_text("x")
        self.assertEqual(self.check(), 1)

    def test_rejects_invalid_package_mode_and_qualification(self):
        self.assertEqual(release_checks.main(
            ["preflight", "--ref", "refs/tags/v0.2.0", "--mode", "trusted",
             "--qualification-subject", self.subject,
             "--qualification-url", "https://example.invalid/q"], repo=self.repo), 1)
        for args in (("--package", "surprise"), ("--mode", "release"),
                     ("--mode", "trusted"),
                     ("--mode", "trusted", "--qualification-subject", self.subject),
                     ("--mode", "trusted", "--qualification-url", "https://example.invalid/q"),
                     ("--mode", "trusted", "--qualification-subject", "0" * 40,
                      "--qualification-url", "https://example.invalid/q"),
                     ("--mode", "trusted", "--qualification-subject", self.subject,
                      "--qualification-url", "http://example.invalid/q"),
                     ("--mode", "trusted", "--qualification-subject", self.subject,
                      "--qualification-url", "https://user:secret@example.invalid/q"),
                     ("--mode", "trusted", "--qualification-subject", self.subject,
                      "--qualification-url", "https:///missing-host")):
            with self.subTest(args=args):
                self.assertNotEqual(self.check(*args), 0)


class CiResultTests(unittest.TestCase):
    def check(self, value):
        return release_checks.main(["ci-results", "--needs-json", value])

    def test_accepts_only_nonempty_all_success_mapping(self):
        self.assertEqual(self.check(json.dumps({"source": {"result": "success"},
                                               "test": {"result": "success"}})), 0)
        for value in ("{}", "[]", "null", "bad", '{"x":{}}',
                      '{"x":{"result":"failure"}}',
                      '{"x":{"result":"cancelled"}}',
                      '{"x":{"result":"skipped"}}',
                      '{"x":{"result":"success"},"y":{"result":"skipped"}}'):
            with self.subTest(value=value):
                self.assertEqual(self.check(value), 1)


if __name__ == "__main__":
    unittest.main()
