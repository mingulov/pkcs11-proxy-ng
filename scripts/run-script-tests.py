#!/usr/bin/env python3
"""Run strict public script regressions, with optional local selection/timings."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
import unittest


ROOT = Path(__file__).resolve().parents[1]
# Direct test dependencies, including the restricted perf-harness tool farm.
# Providers, Docker, gh and network services are replaced by controlled fixtures.
TOOLS = (
    "bash", "git", "jq", "openssl", "timeout", "tar", "gzip", "cargo",
    "sh", "dirname", "mktemp", "mkdir", "rm", "mv", "cat", "touch",
    "awk", "seq", "sort", "chmod", "cksum",
)


def preflight() -> None:
    requirements = (ROOT / "requirements-script-tests.txt").read_text().splitlines()
    expected = next(line.removeprefix("PyYAML==") for line in requirements
                    if line.startswith("PyYAML=="))
    try:
        import yaml
    except ImportError as error:
        raise RuntimeError("PyYAML is required; install requirements-script-tests.txt") from error
    if yaml.__version__ != expected:
        raise RuntimeError(f"PyYAML {expected} is required; found {yaml.__version__}")
    missing = [tool for tool in TOOLS if shutil.which(tool) is None]
    if missing:
        raise RuntimeError(f"missing required tools: {', '.join(missing)}")
    # Check the options the shell harnesses use instead of rejecting compatible
    # coreutils implementations solely because their version banner differs.
    subprocess.run(["timeout", "--signal=TERM", "--kill-after=1s", "1s",
                    sys.executable, "-c", "pass"], text=True, capture_output=True,
                   timeout=10, check=True)


def write_receipt(path: Path | None, report: dict) -> None:
    """Replace the requested receipt atomically, never publishing partial JSON."""
    if path is None:
        return
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=f".{path.name}.", delete=False) as output:
            temporary = Path(output.name)
            json.dump(report, output, indent=2, sort_keys=True, allow_nan=False)
            output.write("\n")
        os.replace(temporary, path)
    except (OSError, ValueError, TypeError) as error:
        raise RuntimeError(f"cannot write timing receipt {path}: {error}") from error
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def collected_ids(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from collected_ids(test)
        else:
            yield test.id()


class TimingResult(unittest.TextTestResult):
    """Observe unittest outcomes, including subtests and untimed fixture holders."""

    _severity = {"running": 0, "passed": 0, "expected_failure": 1, "skipped": 2,
                 "unexpected_success": 3, "failed": 4, "error": 5}

    def __init__(self, *args, report, **kwargs):
        super().__init__(*args, **kwargs)
        self.report = report
        self.active = {}
        self.started = {}

    def startTest(self, test):
        super().startTest(test)
        module = test.__class__.__module__
        if module == "unittest.loader":
            # Failed imports become synthetic test cases named after the module.
            module = test.id().rsplit(".", 1)[-1]
        module = f"{module}.py"
        entry = {"id": test.id(), "status": "running", "duration_seconds": None,
                 "module": module if module in self.report["selected_modules"] else None,
                 "subtests": []}
        self.active[id(test)] = entry
        self.started[id(test)] = time.monotonic()
        self.report["tests"].append(entry)
        self.report["executed_ids"].append(test.id())
        self.report["counts"]["executed"] = self.testsRun

    def stopTest(self, test):
        entry = self.active.pop(id(test))
        entry["duration_seconds"] = time.monotonic() - self.started.pop(id(test))
        if entry["status"] == "running":
            entry["status"] = "incomplete"
        super().stopTest(test)

    def set_status(self, entry, status, detail=None):
        if self._severity[status] >= self._severity[entry["status"]]:
            entry["status"] = status
            if detail is not None:
                entry["detail"] = detail

    def record(self, test, status, detail=None):
        entry = self.active.get(id(test))
        if entry is not None:
            self.set_status(entry, status, detail)
            return
        event = {"id": test.id(), "status": status}
        if detail is not None:
            event["detail"] = detail
        # unittest sends skipped subtests through addSkip, not addSubTest.
        parent = self.active.get(id(getattr(test, "test_case", None)))
        if parent is not None:
            parent["subtests"].append(event)
            self.set_status(parent, status, detail)
        else:
            self.report["fixture_events"].append(event)

    @staticmethod
    def error_detail(error):
        return "".join(traceback.format_exception(*error))[-4000:]

    def addSuccess(self, test):
        super().addSuccess(test)
        self.record(test, "passed")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.report["counts"]["failures"] += 1
        self.record(test, "failed", self.error_detail(err))

    def addError(self, test, err):
        super().addError(test, err)
        self.report["counts"]["errors"] += 1
        self.record(test, "error", self.error_detail(err))

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.report["counts"]["skipped"] += 1
        self.record(test, "skipped", str(reason))

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        self.report["counts"]["expected_failures"] += 1
        self.record(test, "expected_failure", self.error_detail(err))

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self.report["counts"]["unexpected_successes"] += 1
        self.record(test, "unexpected_success")

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        event = {"id": subtest.id(), "status": "passed"}
        if err is not None:
            failure = issubclass(err[0], test.failureException)
            event["status"] = "failed" if failure else "error"
            event["detail"] = self.error_detail(err)
            self.report["counts"]["failures" if failure else "errors"] += 1
            self.set_status(self.active[id(test)], event["status"], event["detail"])
        self.active[id(test)]["subtests"].append(event)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timings-json", type=Path,
                        help="write a timing receipt; the parent directory must exist")
    parser.add_argument("--module", action="append", metavar="test_name.py",
                        help="select an exact local module; repeat to select several")
    args = parser.parse_args(argv)
    report = {
        "format": "script-regressions/v1",
        "scope": "complete" if args.module is None else "selected",
        "status": "running",
        "requested_modules": args.module or [],
        "inventory_modules": [], "selected_modules": [],
        "source_ids": {"runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                       "modules": {}},
        "collected_ids": [], "executed_ids": [], "tests": [], "fixture_events": [],
        "counts": {"collected": 0, "executed": 0, "failures": 0, "errors": 0,
                   "skipped": 0, "expected_failures": 0, "unexpected_successes": 0},
        "collection_errors": [], "collection_duration_seconds": None,
        "run_duration_seconds": None,
        "module_summed_test_duration_seconds": {},
        "summed_test_duration_seconds": 0.0,
        "unattributed_summed_test_duration_seconds": 0.0,
        "module_timing_note": "Sums of individual test durations, excluding import, "
                              "module and class fixture time; not module wall time.",
    }
    exit_code = 2
    receipt_started = False
    try:
        # Clear any old passing receipt before preflight/import/test side effects.
        write_receipt(args.timings_json, report)
        receipt_started = True
        preflight()
        test_root = ROOT / "tests/scripts"
        inventory = {path.name: path for path in sorted(test_root.glob("test_*.py"))
                     if path.is_file()}
        report["inventory_modules"] = list(inventory)
        if args.module is not None:
            if len(set(args.module)) != len(args.module):
                raise RuntimeError("duplicate module selection")
            unknown = [name for name in args.module
                       if name not in inventory or not name.removesuffix(".py").isidentifier()]
            if unknown:
                raise RuntimeError(f"invalid module selection {unknown!r}; "
                                   "use exact test_name.py inventory filenames")
        selected = [name for name in inventory if args.module is None or name in args.module]
        report["selected_modules"] = selected
        report["source_ids"]["modules"] = {
            name: hashlib.sha256(inventory[name].read_bytes()).hexdigest() for name in selected
        }
        loader = unittest.TestLoader()
        started = time.monotonic()
        try:
            if args.module is None:
                suite = loader.discover(str(test_root), pattern="test_*.py")
            else:
                suites = []
                for name in selected:
                    module_suite = loader.discover(str(test_root), pattern=name)
                    if module_suite.countTestCases() == 0:
                        raise RuntimeError(f"zero tests collected from selected module {name}")
                    suites.append(module_suite)
                suite = unittest.TestSuite(suites)
            report["collected_ids"] = list(collected_ids(suite))
        finally:
            report["collection_duration_seconds"] = time.monotonic() - started
            report["collection_errors"] = loader.errors
        count = suite.countTestCases()
        report["counts"]["collected"] = count
        if count == 0:
            raise RuntimeError("zero tests collected from tests/scripts")
        # A hard exit during a test still leaves a current, nonpassing inventory.
        write_receipt(args.timings_json, report)
        scope = ("complete scope" if args.module is None else
                 "selected scope: " + ", ".join(selected))
        print(f"Collected {count} script regression tests ({scope})", file=sys.stderr)
        runner = unittest.TextTestRunner(
            verbosity=2, resultclass=lambda *a, **kw: TimingResult(*a, report=report, **kw))
        started = time.monotonic()
        try:
            result = runner.run(suite)
        finally:
            report["run_duration_seconds"] = time.monotonic() - started
        if result.skipped:
            print(f"script regression gate refused {len(result.skipped)} unexpected skip(s)",
                  file=sys.stderr)
        execution_complete = (
            result.testsRun == count == len(report["collected_ids"])
            and sorted(report["executed_ids"]) == sorted(report["collected_ids"])
            and all(test["status"] not in ("running", "incomplete") for test in report["tests"]))
        if not execution_complete:
            report["error"] = ("incomplete execution: "
                               f"collected {count}, executed {result.testsRun}")
            print(f"script regression gate refused {report['error']}", file=sys.stderr)
        exit_code = 0 if result.wasSuccessful() and not result.skipped and execution_complete else 1
        report["status"] = "passed" if exit_code == 0 else "failed"
    except KeyboardInterrupt:
        report["status"] = "interrupted"
        report["error"] = "script regression run interrupted"
        print(report["error"], file=sys.stderr)
        exit_code = 130
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        report["status"] = "error"
        report["error"] = str(error)
        print(f"script regression preflight failed: {error}", file=sys.stderr)
    finally:
        module_sums = dict.fromkeys(report["selected_modules"], 0.0)
        for test in report["tests"]:
            duration = test["duration_seconds"]
            if duration is not None:
                report["summed_test_duration_seconds"] += duration
                if test["module"] in module_sums:
                    module_sums[test["module"]] += duration
                else:
                    report["unattributed_summed_test_duration_seconds"] += duration
        report["module_summed_test_duration_seconds"] = module_sums
        if receipt_started:
            try:
                write_receipt(args.timings_json, report)
            except RuntimeError as error:
                print(error, file=sys.stderr)
                exit_code = 2
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
