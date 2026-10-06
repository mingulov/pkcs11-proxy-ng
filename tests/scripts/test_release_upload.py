"""Unit tests for scripts/release-upload.sh.

Covers the retry uploader with a fake `gh` on PATH: create-or-extend
semantics, transient-failure retries, attempt exhaustion, and the
empty-stage refusal. The real endpoint flakes (v0.2.2 lost a batch to
a 10s uploads.github.com connect timeout) are NOT reproduced here;
production runs prove them.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "release-upload.sh"

FAKE_GH = """#!/usr/bin/env bash
echo "$*" >>"$FAKE_GH_LOG"
case "$1 $2" in
  "release view")
    n=$(cat "$FAKE_GH_STATE/view" 2>/dev/null || echo 0)
    echo $((n + 1)) >"$FAKE_GH_STATE/view"
    [ "$n" -lt "${FAKE_GH_VIEW_FAILS:-0}" ] && exit 1
    exit 0
    ;;
  "release create") exit 0 ;;
  "release upload")
    n=$(cat "$FAKE_GH_STATE/upload" 2>/dev/null || echo 0)
    echo $((n + 1)) >"$FAKE_GH_STATE/upload"
    [ "$n" -lt "${FAKE_GH_UPLOAD_FAILS:-0}" ] && exit 1
    exit 0
    ;;
esac
exit 0
"""


@unittest.skipUnless(shutil.which("timeout"), "release-upload.sh needs GNU timeout")
class ReleaseUploadTests(unittest.TestCase):
    def run_upload(self, *, files=("a.tar.gz", "b.json"), view_fails=0,
                   upload_fails=0, attempts=5):
        tmp = Path(tempfile.mkdtemp(prefix="release-upload-test-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        bindir = tmp / "bin"
        bindir.mkdir()
        gh = bindir / "gh"
        gh.write_text(FAKE_GH, encoding="utf-8")
        gh.chmod(0o755)
        state = tmp / "state"
        state.mkdir()
        stage = tmp / "stage"
        stage.mkdir()
        for name in files:
            (stage / name).write_text("payload", encoding="utf-8")
        notes = tmp / "NOTES.md"
        notes.write_text("notes", encoding="utf-8")
        env = dict(os.environ)
        env.update({
            "PATH": f"{bindir}{os.pathsep}{env.get('PATH', '')}",
            "FAKE_GH_LOG": str(tmp / "gh.log"),
            "FAKE_GH_STATE": str(state),
            "FAKE_GH_VIEW_FAILS": str(view_fails),
            "FAKE_GH_UPLOAD_FAILS": str(upload_fails),
            "RELEASE_TAG": "v9.9.9",
            "RELEASE_TITLE": "pkcs11-proxy-ng v9.9.9",
            "RELEASE_NOTES": str(notes),
            "STAGE_DIR": str(stage),
            "UPLOAD_ATTEMPTS": str(attempts),
            "UPLOAD_WINDOW": "30",
            "UPLOAD_BACKOFF": "0",
        })
        proc = subprocess.run([str(SCRIPT)], env=env, text=True,
                              capture_output=True, timeout=120)
        log = Path(tmp / "gh.log")
        calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
        return proc, calls

    def test_creates_missing_release_then_uploads(self):
        proc, calls = self.run_upload(view_fails=1)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        creates = [c for c in calls if c.startswith("release create ")]
        self.assertEqual(len(creates), 1)
        self.assertIn("v9.9.9", creates[0])
        self.assertIn("--title pkcs11-proxy-ng v9.9.9", creates[0])
        self.assertIn("--notes-file ", creates[0])
        uploads = [c for c in calls if c.startswith("release upload ")]
        self.assertEqual(len(uploads), 1)
        self.assertIn("--clobber", uploads[0])
        self.assertIn("a.tar.gz", uploads[0])
        self.assertIn("b.json", uploads[0])

    def test_skips_create_when_release_exists(self):
        proc, calls = self.run_upload(view_fails=0)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual([c for c in calls if c.startswith("release create ")], [])

    def test_retries_transient_upload_failure(self):
        proc, calls = self.run_upload(view_fails=0, upload_fails=2)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        uploads = [c for c in calls if c.startswith("release upload ")]
        self.assertEqual(len(uploads), 3)

    def test_fails_after_attempts_exhausted(self):
        proc, calls = self.run_upload(view_fails=0, upload_fails=9, attempts=3)
        self.assertNotEqual(proc.returncode, 0)
        uploads = [c for c in calls if c.startswith("release upload ")]
        self.assertEqual(len(uploads), 3)

    def test_refuses_empty_stage(self):
        proc, calls = self.run_upload(files=(), view_fails=0)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual([c for c in calls if c.startswith("release upload ")], [])


if __name__ == "__main__":
    unittest.main()
