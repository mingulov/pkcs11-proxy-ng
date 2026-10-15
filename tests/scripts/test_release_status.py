"""Release documentation truthfulness (RO-03).

Once a release is recorded (CHANGELOG entry plus git tag), the
current/versioned release docs must agree with it: no unconditional
"unpublished" prose about recorded releases, versioned notes carry
the published identifiers, advertised shell parses, code fences
balance, and the Kubernetes example stays explicitly non-production.
"""

import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Files whose ```bash blocks must parse and whose fences must balance.
SHELL_CHECKED_FILES = (
    "README.md",
    "doc/release/bundle-install.md",
    "doc/release/mtls-setup.md",
    "doc/release/beta-support-matrix.md",
    "doc/release/crates-io-publishing.md",
    "doc/release/v0.2.2-release-notes.md",
    "doc/release/v0.2.1-release-notes.md",
    "doc/runbooks/operating-pkcs11-proxy-ng.md",
    "examples/k8s/README.md",
    "examples/configs/README.md",
)

# Reconciled files that must not call a recorded release unpublished.
STATUS_CHECKED_FILES = (
    "README.md",
    "doc/release/crates-io-publishing.md",
    "doc/release/v0.2.2-release-notes.md",
    "doc/release/v0.2.1-release-notes.md",
    "doc/release/beta-support-matrix.md",
)

UNPUBLISHED_RE = re.compile(r"\bunpublish(?:ed|ing)?\b|\bnot published\b", re.IGNORECASE)


def changelog_releases():
    """``{version: date}`` for dated CHANGELOG entries (Unreleased excluded)."""
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    return dict(re.findall(r"(?m)^## \[(\d+\.\d+\.\d+)\] - (\d{4}-\d{2}-\d{2})", text))


def git_tag_shas(tag):
    """``(tag_object, peeled_commit)`` for an annotated tag, or None."""
    if shutil.which("git") is None:
        return None
    try:
        tag_object = subprocess.check_output(
            ["git", "rev-parse", tag], cwd=ROOT, text=True).strip()
        peeled = subprocess.check_output(
            ["git", "rev-list", "-n", "1", tag], cwd=ROOT, text=True).strip()
    except subprocess.CalledProcessError:
        return None
    if not re.fullmatch(r"[0-9a-f]{40}", tag_object or ""):
        return None
    if not re.fullmatch(r"[0-9a-f]{40}", peeled or ""):
        return None
    return tag_object, peeled


def bash_blocks(text):
    """Yield ``(index, body)`` for each ```bash fenced block."""
    blocks = []
    current = None
    for line in text.splitlines():
        stripped = line.strip()
        if current is None:
            if stripped == "```bash":
                current = []
        elif stripped.startswith("```"):
            blocks.append(current)
            current = None
        else:
            current.append(line)
    return list(enumerate(blocks))


class ReleaseStatusTests(unittest.TestCase):
    def test_recorded_releases_have_no_unpublished_prose(self):
        releases = changelog_releases()
        self.assertIn("0.2.2", releases, "CHANGELOG must record 0.2.2")
        offenders = []
        for relative in STATUS_CHECKED_FILES:
            text = (ROOT / relative).read_text(encoding="utf-8")
            for match in UNPUBLISHED_RE.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                offenders.append(f"{relative}:{line}: {match.group(0)}")
        self.assertEqual(offenders, [],
                         f"false unpublished prose about recorded releases: {offenders}")

    def test_recorded_release_notes_carry_published_status(self):
        # Every recorded release that ships versioned notes must mark
        # them published/released (v0.1.0 predates versioned notes and
        # is out of scope for this reconciliation).
        for version in changelog_releases():
            notes = ROOT / f"doc/release/v{version}-release-notes.md"
            if not notes.is_file():
                continue
            with self.subTest(version=version):
                status_lines = [line for line in
                                notes.read_text(encoding="utf-8").splitlines()
                                if line.startswith("**Status:")]
                self.assertGreaterEqual(len(status_lines), 1,
                                        f"v{version} notes must carry a **Status: line")
                self.assertRegex(status_lines[0], r"(?i)\b(published|released)\b",
                                 f"v{version} notes must record publication")
                self.assertNotRegex(status_lines[0], r"(?i)unpublished",
                                    f"v{version} status must not say unpublished")

    def test_v022_notes_carry_tag_identities(self):
        shas = git_tag_shas("v0.2.2")
        if shas is None:
            self.skipTest("v0.2.2 tag unavailable in this checkout")
        tag_object, peeled = shas
        notes = (ROOT / "doc/release/v0.2.2-release-notes.md").read_text(encoding="utf-8")
        self.assertIn(tag_object, notes, "v0.2.2 notes must record the tag object")
        self.assertIn(peeled, notes, "v0.2.2 notes must record the peeled commit")

    def test_readme_names_latest_published_release(self):
        releases = changelog_releases()
        latest = sorted(releases)[-1]
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(f"v{latest}", readme,
                      f"README must name the latest published release v{latest}")
        self.assertIn("https://github.com/mingulov/pkcs11-proxy-ng/releases", readme)


class AdvertisedShellTests(unittest.TestCase):
    def test_bash_blocks_parse(self):
        if shutil.which("bash") is None:
            self.skipTest("bash unavailable")
        failures = []
        checked = 0
        for relative in SHELL_CHECKED_FILES:
            text = (ROOT / relative).read_text(encoding="utf-8")
            for index, body in bash_blocks(text):
                checked += 1
                with tempfile.NamedTemporaryFile("w", suffix=".sh",
                                                 delete=False) as handle:
                    handle.write("\n".join(body) + "\n")
                    path = handle.name
                try:
                    result = subprocess.run(["bash", "-n", path], capture_output=True,
                                            text=True)
                finally:
                    Path(path).unlink()
                if result.returncode != 0:
                    failures.append(f"{relative} block {index}: {result.stderr.strip()}")
        self.assertGreater(checked, 0, "must check at least one shell block")
        self.assertEqual(failures, [], f"shell blocks fail bash -n: {failures}")

    def test_code_fences_balance(self):
        failures = []
        for relative in SHELL_CHECKED_FILES:
            text = (ROOT / relative).read_text(encoding="utf-8")
            depth = 0
            for number, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                if not stripped.startswith("```"):
                    continue
                if depth == 0:
                    depth = 1
                elif stripped == "```":
                    depth = 0
                else:
                    failures.append(f"{relative}:{number}: nested fence {stripped}")
            if depth != 0:
                failures.append(f"{relative}: unclosed fence at end of file")
        self.assertEqual(failures, [], f"malformed code fences: {failures}")


class KubernetesDemoMarkingTests(unittest.TestCase):
    def test_k8s_example_stays_explicitly_non_production(self):
        readme = (ROOT / "examples/k8s/README.md").read_text(encoding="utf-8")
        self.assertRegex(readme, r"(?i)not a production",
                         "k8s README must keep its demo-only marking")
        self.assertRegex(readme, r"(?i)\bdemo\b", "k8s README must name the demo scope")


if __name__ == "__main__":
    unittest.main()
