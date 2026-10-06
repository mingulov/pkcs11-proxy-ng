"""Windows ARM64 CI leg tests (cross-platform.yml).

The ``win-arm64`` job gives experimental native ARM64 coverage —
build plus lib suites on ``windows-11-arm`` — mirroring the
``win32`` job's shape. It is deliberately NOT a provider
comparison: the pinned Windows SoftHSM2 module is x64-only and
``NATIVE_FFI_QUALIFIED`` excludes Windows ARM64, so these tests
also pin that the ``compare`` matrix stays x64-only.
"""

from __future__ import annotations

import unittest
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - test env provides PyYAML
    yaml = None

ROOT = Path(__file__).resolve().parents[2]
XPLAT_YML = ROOT / ".github" / "workflows" / "cross-platform.yml"

TARGET = "aarch64-pc-windows-msvc"
RUNNER = "windows-11-arm"
RUST_PIN = "1.98.1"
VS_SHELL_PIN = "egor-tensin/vs-shell@54e4148eac794e4580591c2e0b7750f14b7891fc"
COMPARE_OS = {"ubuntu-26.04", "ubuntu-26.04-arm", "macos-15",
              "windows-2022", "windows-2025"}


def load_workflow():
    if yaml is None:
        raise unittest.SkipTest("PyYAML is required to parse workflows")
    return yaml.safe_load(XPLAT_YML.read_text(encoding="utf-8"))


def run_blocks(job):
    return [step.get("run", "") for step in job.get("steps", [])
            if isinstance(step, dict) and "run" in step]


class WinArm64LegTests(unittest.TestCase):
    def job(self):
        return load_workflow()["jobs"]["win-arm64"]

    def test_leg_runs_native_arm64_experimentally(self):
        job = self.job()
        self.assertEqual(job.get("runs-on"), RUNNER)
        self.assertIn("timeout-minutes", job)
        # Experimental until the first green leg (win32/macOS
        # precedent): failures must not fail the workflow.
        self.assertTrue(job.get("continue-on-error"))

    def test_toolchain_carries_arm64_target(self):
        steps = [step for step in self.job().get("steps", [])
                 if isinstance(step, dict)]
        toolchains = [step for step in steps
                      if "dtolnay/rust-toolchain@" in str(step.get("uses", ""))]
        self.assertEqual(len(toolchains), 1)
        with_ = toolchains[0].get("with", {})
        self.assertEqual(with_.get("toolchain"), RUST_PIN)
        self.assertIn(TARGET, str(with_.get("targets", "")))

    def test_msvc_setup_is_arm64(self):
        steps = [step for step in self.job().get("steps", [])
                 if isinstance(step, dict)]
        shells = [step for step in steps
                  if VS_SHELL_PIN in str(step.get("uses", ""))]
        self.assertEqual(len(shells), 1)
        self.assertEqual(shells[0].get("with", {}).get("arch"), "arm64")
        runs = "\n".join(run_blocks(self.job()))
        self.assertIn("vcruntime140.dll", runs)
        self.assertIn("arm64", runs)

    def test_build_and_suites_target_arm64(self):
        runs = "\n".join(run_blocks(self.job()))
        self.assertIn(f"cargo build --locked --release --target {TARGET} "
                      "-p pkcs11-proxy-ng -p pkcs11-proxy-ng-shim", runs)
        for package in ("pkcs11-proxy-ng-types", "pkcs11-proxy-ng-shim",
                        "pkcs11-proxy-ng-backend", "pkcs11-proxy-ng --lib"):
            with self.subTest(package=package):
                self.assertIn(package, runs)
        self.assertGreaterEqual(runs.count(f"--target {TARGET}"), 5)

    def test_pe_architecture_is_verified(self):
        # An x64 binary running under emulation would still pass
        # tests; the leg must prove it built ARM64 machine code.
        blocks = run_blocks(self.job())
        checks = [block for block in blocks
                  if "dumpbin" in block and "AA64" in block]
        self.assertEqual(len(checks), 1)
        self.assertIn(TARGET, checks[0])

    def test_binaries_upload_with_retention(self):
        steps = [step for step in self.job().get("steps", [])
                 if isinstance(step, dict)]
        uploads = [step for step in steps
                   if "actions/upload-artifact@" in str(step.get("uses", ""))]
        self.assertEqual(len(uploads), 1)
        with_ = uploads[0].get("with", {})
        self.assertIn(TARGET, str(with_.get("path", "")))
        self.assertEqual(with_.get("retention-days"), 14)

    def test_leg_runs_no_provider_comparison(self):
        text = yaml.safe_dump(self.job(), default_flow_style=False)
        self.assertNotIn("ci-direct-vs-proxy.py", text)
        self.assertNotIn("softhsm", text.lower())

    def test_compare_matrix_stays_x64_only(self):
        workflow = load_workflow()
        include = (workflow["jobs"]["compare"].get("strategy", {})
                   .get("matrix", {}).get("include", []))
        seen = {entry.get("os") for entry in include
                if isinstance(entry, dict)}
        self.assertEqual(seen, COMPARE_OS)


if __name__ == "__main__":
    unittest.main()
