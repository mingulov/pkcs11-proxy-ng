"""Command-selection regressions for the tiered test runner (Q06/MAINT-01).

The manual ``all`` tier previously composed only ``--lib``-filtered and
per-package cargo commands, silently omitting the server/backend/shim
integration targets (49 at review time) and every future target added to
those directories. The contract after the fix:

* ``scripts/run-test-tiers.sh all`` runs exactly one canonical
  ``cargo test --workspace --locked`` pass (the non-ignored plain-CI
  surface), letting cargo enumerate targets at execution time;
* a failing cargo run propagates (nonzero exit, no PASS line);
* the focused unit/integration/regression/live selectors stay available
  as documented scoped subsets.

These tests stub out ``cargo`` on PATH, so they are fast and hermetic:
they pin command selection, not Rust execution. The real workspace pass
is exercised by running the ``all`` tier itself.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_SCRIPT = REPO_ROOT / "scripts" / "run-test-tiers.sh"

CANONICAL_ALL_ARGV = ["test", "--workspace", "--locked"]

# Flags that narrow cargo's target selection. Any of these in the all-tier
# command would let the script omit integration targets again.
NARROWING_TOKENS = (
    "--lib",
    "--libs",
    "--bins",
    "--bin",
    "--examples",
    "--example",
    "--tests",
    "--test",
    "--benches",
    "--bench",
    "--doc",
    "-p",
    "--package",
)


def write_cargo_stub(stub_dir: Path, *, exit_code: int, log_name: str = "cargo.log") -> Path:
    """Create an executable ``cargo`` stub that logs argv and exits fixed."""
    stub_dir.mkdir(parents=True, exist_ok=True)
    log_path = stub_dir / log_name
    log_path.write_text("")
    stub = stub_dir / "cargo"
    stub.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$*" >> "{log_path}"\n'
        f"exit {exit_code}\n"
    )
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return log_path


def read_argv_lines(log_path: Path) -> list[list[str]]:
    return [line.split() for line in log_path.read_text().splitlines() if line.strip()]


class RunTestTiersTest(unittest.TestCase):
    maxDiff = 4096

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="q06-test-tiers-")
        self.root = Path(self.temp_dir.name)
        # Overlay workspace: the script under test plus a stub cargo. The
        # script resolves its repo root via its own path, so the overlay
        # proves selection does not depend on the surrounding tree.
        self.workspace = self.root / "workspace"
        (self.workspace / "scripts").mkdir(parents=True)
        self.script = self.workspace / "scripts" / SOURCE_SCRIPT.name
        shutil.copy2(SOURCE_SCRIPT, self.script)
        self.script.chmod(self.script.stat().st_mode | stat.S_IXUSR)
        self.stub_dir = self.root / "stubbin"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def run_tier(
        self,
        tier: str,
        *,
        stub_exit: int = 0,
    ) -> tuple[subprocess.CompletedProcess[str], list[list[str]]]:
        log_path = write_cargo_stub(self.stub_dir, exit_code=stub_exit)
        env = dict(
            os.environ,
            PATH=f"{self.stub_dir}{os.pathsep}{os.environ['PATH']}",
        )
        proc = subprocess.run(
            ["bash", str(self.script), tier],
            cwd=self.workspace,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        return proc, read_argv_lines(log_path)

    def test_all_runs_single_canonical_workspace_command(self) -> None:
        """`all` is exactly one unfiltered `cargo test --workspace --locked`."""
        proc, commands = self.run_tier("all")

        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        self.assertIn("PASS: tier 'all' complete", proc.stdout)
        self.assertEqual(
            commands,
            [CANONICAL_ALL_ARGV],
            msg=f"all-tier must issue one canonical cargo invocation, got: {commands}",
        )
        # The old composition re-ran the focused tiers; `all` must not.
        self.assertNotIn("=== tier: unit ===", proc.stdout)
        self.assertNotIn("=== tier: integration ===", proc.stdout)
        self.assertNotIn("=== tier: regression ===", proc.stdout)

    def test_all_includes_present_and_future_integration_targets(self) -> None:
        """Selection is cargo-side, so on-disk targets old and new are covered.

        The overlay gains a synthetic future integration target per crate.
        Because `all` enumerates nothing itself, the captured command is
        unaffected by which target files exist: cargo selects them at
        execution time, including files added after this test was written.
        """
        future_targets = {
            "server": "zz_q06_future_probe.rs",
            "backend": "zz_q06_future_probe.rs",
            "shim": "zz_q06_future_probe.rs",
        }
        for crate, file_name in future_targets.items():
            tests_dir = self.workspace / "crates" / crate / "tests"
            tests_dir.mkdir(parents=True)
            (tests_dir / file_name).write_text(
                "// Q06 synthetic future integration target.\n"
                "#[test]\nfn q06_future_probe_is_selected() {}\n"
            )

        _proc, commands = self.run_tier("all")

        self.assertEqual(
            len(commands),
            1,
            msg=f"all-tier must issue a single cargo command, got: {commands}",
        )
        argv = commands[0]
        self.assertEqual(argv[:1], ["test"])
        self.assertIn("--workspace", argv)
        self.assertIn("--locked", argv)
        narrowing = [token for token in argv if token in NARROWING_TOKENS]
        self.assertEqual(
            narrowing,
            [],
            msg=f"all-tier command must not narrow target selection, got: {argv}",
        )
        # No trailing test-name filter after `--` either.
        self.assertNotIn("--", argv)

        # Premise guard: the real tree still carries integration targets in
        # exactly the crates the review found omitted, so this test cannot
        # pass vacuously after a layout change.
        for crate in ("server", "backend", "shim"):
            tests_dir = REPO_ROOT / "crates" / crate / "tests"
            self.assertTrue(tests_dir.is_dir(), msg=f"missing {tests_dir}")
            targets = sorted(path.name for path in tests_dir.glob("*.rs"))
            self.assertGreater(len(targets), 0, msg=f"no targets in {tests_dir}")

    def test_all_propagates_cargo_failure(self) -> None:
        """Control: a failing cargo run fails the tier without a PASS line."""
        proc, commands = self.run_tier("all", stub_exit=1)

        self.assertEqual(len(commands), 1, msg=f"expected one cargo call, got: {commands}")
        self.assertNotEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        self.assertNotIn("PASS: tier 'all' complete", proc.stdout + proc.stderr)

    def test_focused_tiers_remain_available(self) -> None:
        """unit/integration/regression stay runnable as scoped subsets."""
        for tier in ("unit", "integration", "regression"):
            with self.subTest(tier=tier):
                proc, commands = self.run_tier(tier)
                self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
                self.assertIn(f"PASS: tier '{tier}' complete", proc.stdout)
                self.assertGreater(len(commands), 0, msg=f"{tier} issued no cargo command")

    def test_all_header_documents_honest_contract(self) -> None:
        """The script header must describe the canonical `all` contract."""
        header = SOURCE_SCRIPT.read_text().split("set -euo pipefail")[0]
        self.assertIn(
            "cargo test --workspace --locked",
            header,
            msg="header must name the canonical all-tier command",
        )
        self.assertNotIn(
            "unit + integration + regression",
            header,
            msg="header must no longer claim all composes the focused tiers",
        )
        self.assertIn(
            "--ignored",
            header,
            msg="header must document where ignored tests run",
        )


if __name__ == "__main__":
    unittest.main()
