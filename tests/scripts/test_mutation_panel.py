"""Exercise the real panel entrypoint; Cargo alone produces controlled artifacts."""

import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/run-mutation-panel.py"
HELPER = ROOT / "scripts/run-native-contracts.py"
CASE = "protected-scanner-always-accept"
BEFORE = "    validate_message(index, payload, 0)\n"
AFTER = "    let _ = (index, payload); Ok(())\n"
SOURCE = "crates/proto/src/protected_decode.rs"
PANIC_SOURCE = "crates/proto/tests/protected_wire_metamorphic.rs"


def identity(path):
    stat = path.stat()
    return stat.st_dev, stat.st_ino, hashlib.sha256(path.read_bytes()).hexdigest()


class MutationPanelTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mutation-panel-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / "repo"
        self.tools = self.base / "tools"
        self.tools.mkdir()
        for directory in ("scripts", "tests", "crates/proto/src", "crates/proto/tests"):
            (self.repo / directory).mkdir(parents=True, exist_ok=True)
        (self.repo / SOURCE).write_text("pub fn validate() {\n" + BEFORE + "}\n")
        (self.repo / PANIC_SOURCE).write_text("// independent primary/control assertions\n")
        (self.repo / "Cargo.toml").write_text("[workspace]\nmembers = []\n")
        (self.repo / "Cargo.lock").write_text("version = 4\n")
        (self.repo / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "1.98.1"\n')
        self.output = self.base / "receipt.json"
        self.status = self.base / "status"
        self.status.write_bytes(b"")
        self.pid_file = self.base / "child.pid"
        self.ready = self.base / "ready"
        self.donor = self.repo / "target"
        self.donor.mkdir()
        (self.donor / "cache-sentinel").write_bytes(b"ordinary cache stays intact\n")
        self.manifest = {
            "schema": "mutation-panel-manifest/v1",
            "cases": [
                {
                    "id": CASE,
                    "source": SOURCE,
                    "before": BEFORE,
                    "after": AFTER,
                    "package": "pkcs11-proxy-ng-proto",
                    "target": {"kind": "test", "name": "protected_wire_metamorphic"},
                    "primary": "primary_case",
                    "control": "control_case",
                    "panic": {
                        "source": PANIC_SOURCE,
                        "fragments": [
                            "assertion `left == right` failed: value=0 field=0",
                            "left: Ok(())",
                            'right: Err(DuplicateField { message: "LoginRequest", number: 1 })',
                        ],
                    },
                }
            ],
        }
        self.write_manifest()
        self.write_tool(
            "git",
            """
            import os, pathlib, sys, tarfile
            root = pathlib.Path(os.environ['FIXTURE_REPO'])
            args = sys.argv[1:]
            if args == ['rev-parse', '--show-toplevel']:
                print(root)
            elif args[:3] == ['rev-parse', '--verify', '--end-of-options']:
                print('a' * 40)
            elif args[:1] == ['status']:
                sys.stdout.buffer.write(pathlib.Path(os.environ['FIXTURE_STATUS']).read_bytes())
            elif args == ['ls-files', '-z', '--cached']:
                names = ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml',
                         'crates/proto/src/protected_decode.rs',
                         'crates/proto/tests/protected_wire_metamorphic.rs']
                for name in ('AGENTS.md', 'CLAUDE.md'):
                    if (root / name).exists() or (root / name).is_symlink(): names.append(name)
                if (root / 'examples').exists():
                    for directory, dirs, files in os.walk(root / 'examples'):
                        for name in dirs[:]:
                            path = pathlib.Path(directory) / name
                            if path.is_symlink():
                                names.append(path.relative_to(root).as_posix())
                                dirs.remove(name)
                        names.extend((pathlib.Path(directory) / name).relative_to(root).as_posix()
                                     for name in files)
                for name in names:
                    sys.stdout.buffer.write(name.encode() + b'\\0')
            elif args[:2] == ['archive', '--format=tar']:
                target = next(a.split('=', 1)[1] for a in args if a.startswith('--output='))
                with tarfile.open(target, 'w') as archive:
                    for name in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'crates'):
                        archive.add(root / name, arcname=name)
                    for name in ('AGENTS.md', 'CLAUDE.md', 'examples'):
                        if (root / name).exists() or (root / name).is_symlink():
                            archive.add(root / name, arcname=name)
                    if os.environ['FIXTURE_MODE'] == 'archive_symlink':
                        link = tarfile.TarInfo('escaping-link')
                        link.type = tarfile.SYMTYPE
                        link.linkname = str(root / 'Cargo.toml')
                        archive.addfile(link)
                    mode = os.environ['FIXTURE_MODE']
                    links = {'archive_escape': [('link.toml', '../outside.toml')],
                             'archive_cycle': [('a.toml', 'b.toml'), ('b.toml', 'a.toml')],
                             'archive_directory': [('link.toml', 'crates')]}.get(mode, [])
                    for name, target in links:
                        link = tarfile.TarInfo(name)
                        link.type = tarfile.SYMTYPE
                        link.linkname = target
                        archive.addfile(link)
                    if mode in ('archive_hardlink', 'archive_special'):
                        member = tarfile.TarInfo('unsupported.toml')
                        member.type = tarfile.LNKTYPE if mode == 'archive_hardlink' else tarfile.FIFOTYPE
                        member.linkname = 'Cargo.toml'
                        archive.addfile(member)
            else:
                raise SystemExit('unexpected git arguments: ' + repr(args))
        """,
        )
        self.write_tool(
            "rustup",
            """
            import os, pathlib, sys
            if sys.argv[1:4] != ['which', '--toolchain', '1.98.1']:
                raise SystemExit('wrong pinned toolchain request')
            print('malformed\\nselector' if os.environ['FIXTURE_MODE'] == 'bad_tool_selector'
                  else pathlib.Path(os.environ['FIXTURE_TOOLS']) / sys.argv[4])
        """,
        )
        self.write_tool("rustc", "print('rustc 1.98.1 (fixture)')\n")
        self.write_tool(
            "cp",
            """
            import os, pathlib, shutil, sys
            if sys.argv[1:3] != ['--reflink=always', '-a']:
                raise SystemExit('clone must require reflinks')
            source, target = pathlib.Path(sys.argv[3]), pathlib.Path(sys.argv[4])
            shutil.copytree(source, target, dirs_exist_ok=True,
                            copy_function=os.link if os.environ['FIXTURE_MODE'] == 'hardlink_clone'
                            else shutil.copy2)
        """,
        )
        self.binary_template = self.base / "binary-template"
        self.binary_template.write_text(
            "#!"
            + sys.executable
            + "\n"
            + textwrap.dedent("""
            import os, pathlib, signal, subprocess, sys, time
            mode = os.environ['FIXTURE_MODE']
            mutant = pathlib.Path(__file__).name.startswith('mutant-')
            if '--list' in sys.argv:
                if mode != 'missing': print('primary_case: test')
                print('control_case: test')
                raise SystemExit(0)
            name = sys.argv[sys.argv.index('--exact') + 1]
            assert '--test-threads=1' in sys.argv and '--nocapture' in sys.argv
            if mutant and name == 'primary_case':
                if mode == 'new_dirty_source':
                    pathlib.Path(os.environ['FIXTURE_STATUS']).write_bytes(b'?? crates/new.rs\\0')
                if mode == 'helper_change':
                    helper = pathlib.Path(os.environ['FIXTURE_REPO']) / 'scripts/run-native-contracts.py'
                    helper.write_text(helper.read_text() + '\\n# changed during run\\n')
                if mode == 'detached_exit':
                    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'],
                                             start_new_session=True)
                    pathlib.Path(os.environ['FIXTURE_PID']).write_text(str(child.pid))
                if mode in ('timeout', 'detached', 'interrupt'):
                    if mode == 'detached':
                        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'],
                                                 start_new_session=True)
                        pathlib.Path(os.environ['FIXTURE_PID']).write_text(str(child.pid))
                    pathlib.Path(os.environ['FIXTURE_READY']).write_text('ready')
                    time.sleep(60)
                if mode == 'signal': os.kill(os.getpid(), signal.SIGTERM)
                if mode == 'zero':
                    print('running 0 tests')
                    print('test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out')
                    raise SystemExit(0)
                if mode == 'ignored':
                    print('running 1 test')
                    print('test primary_case ... ignored')
                    print('test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out')
                    raise SystemExit(0)
                if mode != 'survived':
                    print('running 1 test')
                    print('test primary_case ... ' if mode == 'rust_panic_layout' else 'test primary_case ... FAILED')
                    print("thread 'primary_case' (12345) panicked at crates/proto/tests/protected_wire_metamorphic.rs:35:17:"
                          if mode == 'rust_panic_layout' else
                          "thread 'primary_case' panicked at crates/proto/tests/protected_wire_metamorphic.rs:35:17:")
                    print('assertion `left == right` failed: value=0 field=0')
                    print('  left: Ok(())')
                    print(' right: Err(DuplicateField { message: "LoginRequest", number: 1 })'
                          if mode != 'wrong_panic' else ' right: unrelated expectation')
                    print('test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out')
                    if mode == 'extra_terminal':
                        print('test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out')
                    raise SystemExit(101)
            print('running 1 test')
            print('test ' + name + ' ... ok')
            print('test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out')
        """)
        )
        self.write_tool(
            "cargo",
            """
            import json, os, pathlib, shutil, sys
            args = sys.argv[1:]
            if args == ['--version']:
                print('cargo 1.98.1 (fixture)')
                raise SystemExit(0)
            root = pathlib.Path.cwd()
            target = pathlib.Path(os.environ['CARGO_TARGET_DIR']).resolve()
            build = pathlib.Path(os.environ['CARGO_BUILD_BUILD_DIR']).resolve()
            original = pathlib.Path(os.environ['FIXTURE_REPO']).resolve()
            if target.is_relative_to(original) or build.is_relative_to(original):
                raise SystemExit('normal output selected')
            if build != target / 'build' or os.environ['CARGO_BUILD_JOBS'] != '2':
                raise SystemExit('both dedicated output roots are required')
            if os.environ.get('RUSTC') != str(pathlib.Path(os.environ['FIXTURE_TOOLS']) / 'rustc'):
                raise SystemExit('unpinned compiler')
            if 'RUSTC_WRAPPER' in os.environ or 'RUSTUP_TOOLCHAIN' in os.environ:
                raise SystemExit('inherited compiler selector leaked')
            if args[:1] == ['clean']:
                if args != ['clean', '--locked', '--offline', '-p', 'pkcs11-proxy-ng-proto', '--profile', 'dev']:
                    raise SystemExit('wrong selected clean')
                target.mkdir(parents=True, exist_ok=True)
                (target / 'selected-package-cleaned').write_text('yes')
                raise SystemExit(0)
            expected = ['test', '--locked', '--offline', '--no-run', '--message-format=json',
                        '-p', 'pkcs11-proxy-ng-proto', '--test', 'protected_wire_metamorphic']
            if args != expected or not (target / 'selected-package-cleaned').exists():
                raise SystemExit('wrong build or selected package was not invalidated')
            mutant = 'let _ = (index, payload); Ok(())' in (root / 'crates/proto/src/protected_decode.rs').read_text()
            mode = os.environ['FIXTURE_MODE']
            if mode == 'internal_links':
                for alias, source_target in [('CLAUDE.md', 'AGENTS.md'),
                                      ('examples/cloudhsm-mechanisms.toml', 'examples/vendors/aws-cloudhsm.toml')]:
                    alias, source_target = root / alias, root / source_target
                    if (alias.is_symlink() or not alias.is_file() or alias.read_bytes() != source_target.read_bytes()
                            or alias.stat().st_ino == source_target.stat().st_ino):
                        raise SystemExit('committed source links need independent private regular bytes')
            if mutant and mode == 'build_error':
                print('error: controlled compiler failure')
                print(json.dumps({'reason': 'build-finished', 'success': False}))
                raise SystemExit(101)
            if mode == 'bad_build_json':
                print('{malformed compiler output')
                raise SystemExit(0)
            binary = target / ('mutant-test' if mutant else 'baseline-test')
            shutil.copyfile(os.environ['FIXTURE_BINARY'], binary)
            binary.chmod(0o700)
            message = {'reason': 'compiler-artifact',
                       'target': {'name': 'protected_wire_metamorphic', 'kind': ['test']},
                       'profile': {'test': True}, 'executable': str(binary),
                       'filenames': [str(binary)], 'fresh': mode == 'fresh'}
            if mode == 'outside_artifact': message['executable'] = str(original / 'Cargo.toml')
            if mode == 'contradictory_build':
                print(json.dumps({'reason': 'compiler-message', 'message': {'level': 'error'}}))
            print(json.dumps(message))
            print(json.dumps({'reason': 'build-finished', 'success': True}))
        """,
        )

    def write_tool(self, name, source):
        path = self.tools / name
        path.write_text("#!" + sys.executable + "\n" + textwrap.dedent(source))
        path.chmod(0o700)

    def write_manifest(self):
        (self.repo / "tests/mutation-panel.json").write_text(json.dumps(self.manifest))

    def launch(
        self, mode="killed", extra=(), timeout="4", injection=None, wait=True, helper_override=None
    ):
        self.assertTrue(SCRIPT.is_file(), "mutation panel entrypoint must exist")
        shutil.copy2(SCRIPT, self.repo / "scripts/run-mutation-panel.py")
        shutil.copy2(HELPER, self.repo / "scripts/run-native-contracts.py")
        if helper_override is not None:
            (self.repo / "scripts/run-native-contracts.py").write_text(helper_override)
        env = dict(
            os.environ,
            PATH=str(self.tools),
            FIXTURE_MODE=mode,
            FIXTURE_REPO=str(self.repo),
            FIXTURE_TOOLS=str(self.tools),
            FIXTURE_STATUS=str(self.status),
            FIXTURE_BINARY=str(self.binary_template),
            FIXTURE_PID=str(self.pid_file),
            FIXTURE_READY=str(self.ready),
            RUSTC_WRAPPER="/hostile/wrapper",
            RUSTUP_TOOLCHAIN="hostile",
            CARGO_TARGET_DIR=str(self.donor),
            CARGO_BUILD_BUILD_DIR=str(self.donor / "build"),
        )
        # Isolate the coordination path from real builds. Kernel locking and
        # the entrypoint's ownership/cleanup code still execute unchanged.
        launcher = self.base / "inject.py"
        launcher.write_text(
            "import os\noriginal_open = os.open\n"
            "def fixture_open(path, *args, **kwargs):\n"
            "    if os.fspath(path) == '/tmp/pkcs11-proxy-testing-feedback-cargo.lock':\n"
            "        path = " + repr(str(self.base / "donor.lock")) + "\n"
            "    return original_open(path, *args, **kwargs)\n"
            "os.open = fixture_open\n"
            + (injection or "")
            + "\nimport runpy\nrunpy.run_path("
            + repr(str(self.repo / "scripts/run-mutation-panel.py"))
            + ', run_name="__main__")\n'
        )
        command = [
            sys.executable,
            str(launcher),
            "--output",
            str(self.output),
            "--timeout=" + timeout,
            *extra,
        ]
        if not wait:
            return subprocess.Popen(
                command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
        result = subprocess.run(command, env=env, text=True, capture_output=True, timeout=12)
        self.assertTrue(self.output.is_file(), result.stdout + result.stderr)
        return result, json.loads(self.output.read_text())

    def assert_failed(self, mode, expected=None, **kwargs):
        result, receipt = self.launch(mode, **kwargs)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(receipt["status"], "failed")
        if expected:
            self.assertIn(expected, receipt.get("error", "") + json.dumps(receipt["cases"]))
        return receipt

    def test_killed_receipt_binds_artifacts_counts_sources_and_preserves_inputs(self):
        before = {
            path: identity(path)
            for path in (
                self.repo / SOURCE,
                self.repo / PANIC_SOURCE,
                self.donor / "cache-sentinel",
            )
        }
        result, receipt = self.launch(extra=("--seed-target", str(self.donor)))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(receipt["status"], "passed")
        self.assertEqual(receipt["selected_ids"], [CASE])
        self.assertEqual(receipt["executed_ids"], [CASE])
        self.assertEqual(receipt["cases"][0]["status"], "killed")
        self.assertEqual(receipt["source"]["commit"], "a" * 40)
        self.assertIn("archive_sha256", receipt["source"])
        self.assertIn("manifest_sha256", receipt)
        self.assertIn("helper_sha256", receipt)
        self.assertEqual(len(receipt["cases"][0]["variants"]), 2)
        for variant in receipt["cases"][0]["variants"]:
            self.assertEqual(len(variant["artifact"]["sha256"]), 64)
            self.assertTrue(variant["removed"])
            self.assertFalse(Path(variant["source_path"]).exists())
            self.assertFalse(Path(variant["target_path"]).exists())
            self.assertEqual(len(variant["tests"]), 2)
        self.assertTrue(receipt["cleanup"]["complete"])
        self.assertTrue(receipt["caller_unchanged"])
        self.assertTrue(receipt["donor"]["unchanged"])
        self.assertEqual(before, {path: identity(path) for path in before})
        for command in receipt["commands"]:
            self.assertTrue(command["cleanup_complete"])
            self.assertEqual(len(command["log_sha256"]), 64)

    def test_committed_internal_source_links_are_materialized_with_provenance(self):
        (self.repo / "AGENTS.md").write_text("fixture contributor rules\n")
        (self.repo / "CLAUDE.md").symlink_to("AGENTS.md")
        vendors = self.repo / "examples/vendors"
        vendors.mkdir(parents=True)
        (vendors / "aws-cloudhsm.toml").write_text("[mechanisms]\nfixture = true\n")
        (self.repo / "examples/cloudhsm-mechanisms.toml").symlink_to("vendors/aws-cloudhsm.toml")
        expected = {
            "CLAUDE.md": ("AGENTS.md", "AGENTS.md"),
            "examples/cloudhsm-mechanisms.toml": (
                "vendors/aws-cloudhsm.toml",
                "examples/vendors/aws-cloudhsm.toml",
            ),
        }
        before = {
            name: ((self.repo / name).lstat().st_ino, (self.repo / name).readlink())
            for name in expected
        }
        targets = {name: identity(self.repo / target) for name, (_, target) in expected.items()}
        result, receipt = self.launch("internal_links")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(receipt["status"], "passed")
        self.assertTrue(receipt["caller_unchanged"])
        self.assertTrue(receipt["cleanup"]["complete"])
        self.assertEqual(set(receipt["source"]["links"]), set(expected))
        for name, (literal, target) in expected.items():
            provenance = receipt["source"]["links"][name]
            self.assertEqual(provenance["link_target"], literal)
            self.assertEqual(provenance["resolved_target"], target)
            self.assertEqual(
                provenance["literal_sha256"], hashlib.sha256(literal.encode()).hexdigest()
            )
            self.assertEqual(provenance["target_sha256"], targets[name][2])
            self.assertEqual(receipt["source"]["files"][name]["sha256"], targets[name][2])
            self.assertEqual(receipt["source"]["files"][name]["source_link"], provenance)
            self.assertEqual(receipt["caller_sources"][name]["source_link"], provenance)
            self.assertEqual(
                ((self.repo / name).lstat().st_ino, (self.repo / name).readlink()), before[name]
            )
            self.assertEqual(identity(self.repo / target), targets[name])

    def test_source_link_escapes_cycles_directories_and_archive_specials_are_refused(self):
        outside = self.base / "outside.toml"
        outside.write_text("outside sentinel\n")
        before = identity(outside)
        for mode in (
            "source_escape",
            "source_cycle",
            "source_directory",
            "archive_escape",
            "archive_cycle",
            "archive_directory",
            "archive_hardlink",
            "archive_special",
        ):
            with self.subTest(mode=mode):
                examples = self.repo / "examples"
                shutil.rmtree(examples, ignore_errors=True)
                examples.mkdir()
                if mode == "source_escape":
                    (examples / "link.toml").symlink_to("../../outside.toml")
                if mode == "source_cycle":
                    (examples / "a.toml").symlink_to("b.toml")
                    (examples / "b.toml").symlink_to("a.toml")
                if mode == "source_directory":
                    (examples / "vendors").mkdir()
                    (examples / "vendors/file.toml").write_text("fixture\n")
                    (examples / "link.toml").symlink_to("vendors")
                receipt = self.assert_failed(mode)
                self.assertTrue(receipt["cleanup"]["complete"])
                self.assertEqual(receipt["executed_ids"], [])
                self.assertFalse(
                    any(
                        command["kind"] in ("toolchain", "clone", "clean-package", "build", "test")
                        for command in receipt["commands"]
                    )
                )
                self.assertEqual(identity(outside), before)

    def test_surviving_primary_is_not_a_kill(self):
        receipt = self.assert_failed("survived", "survived")
        self.assertEqual(receipt["cases"][0]["status"], "survived")

    def test_actual_rust_panic_layout_with_thread_id_is_admitted(self):
        result, receipt = self.launch("rust_panic_layout")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(receipt["cases"][0]["status"], "killed")

    def test_compile_failure_is_never_a_kill(self):
        receipt = self.assert_failed("build_error", "build")
        self.assertNotIn("killed", [case["status"] for case in receipt["cases"]])

    def test_malformed_tool_helper_and_build_outputs_are_errors(self):
        for mode in (
            "bad_tool_selector",
            "bad_build_json",
            "archive_symlink",
            "contradictory_build",
        ):
            with self.subTest(mode=mode):
                receipt = self.assert_failed(mode)
                self.assertNotIn("killed", [case["status"] for case in receipt["cases"]])
        self.assert_failed(
            "killed", "primitive", helper_override="def prepare_child_ownership(): pass\n"
        )
        self.assert_failed(
            "killed",
            helper_override=HELPER.read_text().replace(
                "return root_running, sorted(observed), reaped", 'return "malformed"'
            ),
        )

    def test_wrong_panic_zero_ignored_signal_and_bad_artifacts_fail(self):
        for mode in (
            "wrong_panic",
            "zero",
            "ignored",
            "signal",
            "fresh",
            "outside_artifact",
            "extra_terminal",
            "missing",
        ):
            with self.subTest(mode=mode):
                receipt = self.assert_failed(mode)
                self.assertTrue(receipt["cleanup"]["complete"])
                self.assertNotIn("killed", [case["status"] for case in receipt["cases"]])

    def test_timeout_and_detached_descendant_are_reaped(self):
        for mode in ("timeout", "detached"):
            with self.subTest(mode=mode):
                self.pid_file.unlink(missing_ok=True)
                self.ready.unlink(missing_ok=True)
                receipt = self.assert_failed(mode, "timeout", timeout="2")
                self.assertTrue(self.ready.exists(), "selected child must enter before its timeout")
                self.assertTrue(receipt["cleanup"]["complete"])
                if mode == "detached":
                    self.assertTrue(self.pid_file.exists(), "detached child must actually launch")
                    self.assertFalse(Path("/proc/" + self.pid_file.read_text()).exists())
        receipt = self.assert_failed("detached_exit", "descendant")
        self.assertTrue(receipt["cleanup"]["complete"])
        self.assertFalse(Path("/proc/" + self.pid_file.read_text()).exists())

    def test_signal_interrupt_replaces_stale_pass_and_cleans(self):
        self.output.write_text('{"status": "passed"}\n')
        process = self.launch("interrupt", timeout="8", wait=False)
        deadline = time.monotonic() + 5
        while not self.ready.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(self.ready.exists(), "fixture child must enter before interrupt")
        self.assertEqual(json.loads(self.output.read_text())["status"], "running")
        process.send_signal(signal.SIGTERM)
        process.communicate(timeout=5)
        self.assertNotEqual(process.returncode, 0)
        receipt = json.loads(self.output.read_text())
        self.assertEqual(receipt["status"], "failed")
        self.assertTrue(receipt["cleanup"]["complete"])

    def test_creation_boundary_interrupts_retire_entered_child_before_and_after_assignment(self):
        ownership = runpy.run_path(str(HELPER))
        for boundary in ("before_return", "after_assignment"):
            with self.subTest(boundary=boundary):
                ownership["prepare_child_ownership"]()
                self.pid_file.unlink(missing_ok=True)
                self.ready.unlink(missing_ok=True)
                injection = textwrap.dedent("""
                    import signal, subprocess, sys, time
                    from pathlib import Path
                    real_popen = subprocess.Popen
                    boundary_fired = False
                    def selected(process):
                        return (str(process.args[0]).endswith('mutant-test')
                                and '--exact' in process.args and 'primary_case' in process.args)
                    def send_boundary(process):
                        global boundary_fired
                        boundary_fired = True
                        os.kill(os.getpid(), signal.SIGTERM if BOUNDARY == 'before_return' else signal.SIGINT)
                    def popen_boundary(*args, **kwargs):
                        process = real_popen(*args, **kwargs)
                        if selected(process):
                            Path(os.environ['FIXTURE_PID']).write_text(str(process.pid))
                            real_wait = process.wait
                            def guarded_wait(*args, **kwargs):
                                if all(signal.getsignal(s) == signal.SIG_IGN
                                       for s in (signal.SIGINT, signal.SIGTERM)):
                                    Path(os.environ['FIXTURE_READY'] + '.repeated').write_text('sent')
                                    for _ in range(3):
                                        os.kill(os.getpid(), signal.SIGINT)
                                        os.kill(os.getpid(), signal.SIGTERM)
                                return real_wait(*args, **kwargs)
                            process.wait = guarded_wait
                            deadline = time.monotonic() + 3
                            while not Path(os.environ['FIXTURE_READY']).exists():
                                if process.poll() is not None or time.monotonic() >= deadline:
                                    raise RuntimeError('boundary child never entered')
                                time.sleep(0.005)
                            if BOUNDARY == 'before_return':
                                send_boundary(process)
                        return process
                    subprocess.Popen = popen_boundary
                    def trace_boundary(frame, event, arg):
                        if (BOUNDARY == 'after_assignment' and not boundary_fired
                                and event == 'line' and frame.f_code.co_name == 'run'
                                and Path(frame.f_code.co_filename).name == 'run-mutation-panel.py'):
                            process = frame.f_locals.get('process')
                            if process is not None and selected(process):
                                send_boundary(process)
                        return trace_boundary
                    if BOUNDARY == 'after_assignment':
                        sys.settrace(trace_boundary)
                """).replace("BOUNDARY", repr(boundary))
                receipt = None
                pid = None
                try:
                    result, receipt = self.launch("interrupt", timeout="8", injection=injection)
                    self.assertTrue(self.ready.exists(), "real selected child must enter")
                    self.assertTrue(
                        self.pid_file.exists(), "created child identity must be recorded"
                    )
                    pid = int(self.pid_file.read_text())
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(receipt["status"], "failed")
                    self.assertFalse(Path(f"/proc/{pid}").exists(), "entered child must be reaped")
                    self.assertTrue(receipt["cleanup"]["complete"])
                    self.assertTrue(receipt["cleanup"]["ephemeral_root_removed"])
                    self.assertTrue(receipt["caller_unchanged"])
                    self.assertFalse(Path(receipt["ephemeral_root"]).exists())
                    self.assertTrue(
                        Path(str(self.ready) + ".repeated").exists(),
                        "repeated INT/TERM must be exercised during actual settlement",
                    )
                    command = next(c for c in receipt["commands"] if c.get("pid") == pid)
                    self.assertTrue(command["cleanup_complete"])
                    self.assertTrue(command["root_killed"])
                finally:
                    # Rescue only this fixture's adopted children on assertion-first RED.
                    for child in ownership["owned_children"]():
                        ownership["kill_owned_pid"](child)
                        deadline = time.monotonic() + 3
                        while True:
                            try:
                                reaped, _ = os.waitpid(child, os.WNOHANG)
                            except ChildProcessError:
                                break
                            if reaped:
                                break
                            if time.monotonic() >= deadline:
                                raise AssertionError(
                                    "boundary fixture rescue could not reap owned child"
                                )
                            time.sleep(0.005)
                    if receipt and receipt.get("ephemeral_root"):
                        shutil.rmtree(receipt["ephemeral_root"], ignore_errors=True)
                    Path(str(self.ready) + ".repeated").unlink(missing_ok=True)
                self.assertEqual(ownership["owned_children"](), [])

    def test_missing_tool_and_invalid_timeouts_refuse_without_builds(self):
        for timeout in ("nan", "inf", "-inf", "0", "-1"):
            with self.subTest(timeout=timeout):
                receipt = self.assert_failed("killed", "timeout", timeout=timeout)
                self.assertEqual(receipt["commands"], [])
                self.assertEqual(receipt["executed_ids"], [])
        (self.tools / "rustup").unlink()
        receipt = self.assert_failed("killed", "rustup")
        self.assertEqual(receipt["executed_ids"], [])

    def test_malformed_cli_invalidates_stale_pass(self):
        for extra in (("--timeout=invalid",), ("--unknown-option",), ("--seed-target",)):
            with self.subTest(extra=extra):
                self.output.write_text('{"status": "passed"}\n')
                receipt = self.assert_failed("killed", extra=extra)
                self.assertEqual(receipt["commands"], [])

    def test_malformed_seed_cannot_replace_a_known_donor_file(self):
        self.output = self.donor / "receipt.json"
        self.output.write_text('{"status":"passed","prior_run":"donor sentinel"}\n')
        before = identity(self.output)
        result, _ = self.launch(extra=("--seed-target", str(self.donor), "--seed-target"))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(identity(self.output), before)

    def test_changed_helper_and_new_dirty_source_cannot_pass(self):
        for mode in ("helper_change", "new_dirty_source"):
            with self.subTest(mode=mode):
                receipt = self.assert_failed(mode)
                self.assertTrue(receipt["cleanup"]["ephemeral_root_removed"])

    def test_hardlink_seed_is_rejected_without_poisoning_donor(self):
        original = identity(self.donor / "cache-sentinel")
        self.assert_failed("hardlink_clone", "inode", extra=("--seed-target", str(self.donor)))
        self.assertEqual(identity(self.donor / "cache-sentinel"), original)

    def test_malformed_manifest_and_duplicate_or_unknown_selections_refuse(self):
        for extra in (("--case", "absent"), ("--case", CASE, "--case", CASE)):
            with self.subTest(extra=extra):
                receipt = self.assert_failed("killed", extra=extra)
                self.assertEqual(receipt["executed_ids"], [])
        for change in ("empty", "unknown_field", "escape", "same_replacement"):
            with self.subTest(change=change):
                manifest = json.loads(json.dumps(self.manifest))
                if change == "empty":
                    manifest["cases"] = []
                if change == "unknown_field":
                    manifest["cases"][0]["shell"] = "unsafe"
                if change == "escape":
                    manifest["cases"][0]["source"] = "../outside.rs"
                if change == "same_replacement":
                    manifest["cases"][0]["after"] = BEFORE
                (self.repo / "tests/mutation-panel.json").write_text(json.dumps(manifest))
                receipt = self.assert_failed("killed")
                self.assertEqual(receipt["commands"], [])
        self.write_manifest()

    def test_dirty_source_and_renamed_old_source_are_refused(self):
        for status in (
            b" M crates/proto/src/protected_decode.rs\0",
            b" M crates/proto/fixtures/wire-case.json\0",
            b"?? tests/ffi_oracles/new/fixture.txt\0",
            b"R  note.txt\0crates/proto/src/old.rs\0",
        ):
            with self.subTest(status=status):
                self.status.write_bytes(status)
                receipt = self.assert_failed("killed", "dirty")
                self.assertEqual(receipt["executed_ids"], [])
        self.status.write_bytes(b" M doc/development.md\0?? scripts/run-mutation-panel.py\0")
        result, _ = self.launch()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_ambiguous_anchor_and_escaping_donor_link_refuse(self):
        (self.repo / SOURCE).write_text(BEFORE + BEFORE)
        self.assert_failed("killed", "anchor")
        (self.repo / SOURCE).write_text("pub fn validate() {\n" + BEFORE + "}\n")
        (self.donor / "escape").symlink_to(self.repo / SOURCE)
        self.assert_failed("killed", "symlink", extra=("--seed-target", str(self.donor)))

    def test_cleanup_failure_overrides_success(self):
        injection = (
            "import shutil\noriginal = shutil.rmtree\n"
            "def fail(path, *a, **kw):\n"
            "    if 'pkcs11-mutation-panel-' in str(path): raise OSError('induced cleanup failure')\n"
            "    return original(path, *a, **kw)\nshutil.rmtree = fail\n"
        )
        receipt = self.assert_failed("killed", "cleanup", injection=injection)
        self.addCleanup(shutil.rmtree, receipt["ephemeral_root"], ignore_errors=True)
        self.assertFalse(receipt["cleanup"]["complete"])

    def test_cleanup_uses_finite_cache_sized_budget_and_records_synchronous_timing(self):
        timer_log = self.base / "cleanup-timer.json"
        finished = self.base / "cleanup-finished"
        injection = (
            "import json, signal, shutil\nfrom pathlib import Path\n"
            "real_timer = signal.setitimer\nreal_remove = shutil.rmtree\n"
            "def recorded_timer(which, seconds, interval=0):\n"
            "    if seconds > 0:\n"
            "        Path(" + repr(str(timer_log)) + ").write_text(json.dumps(seconds))\n"
            "    return real_timer(which, seconds, interval)\n"
            "def recorded_remove(path, *args, **kwargs):\n"
            "    result = real_remove(path, *args, **kwargs)\n"
            '    if "pkcs11-mutation-panel-" in str(path):\n'
            "        Path(" + repr(str(finished)) + ').write_text("removed")\n'
            "    return result\n"
            "signal.setitimer = recorded_timer\nshutil.rmtree = recorded_remove\n"
        )
        result, receipt = self.launch(injection=injection)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(timer_log.read_text()), 60)
        self.assertTrue(finished.exists(), "removal must finish before the runner returns")
        self.assertIn("ephemeral_removal", receipt["cleanup"])
        removal = receipt["cleanup"]["ephemeral_removal"]
        self.assertEqual(removal["budget_seconds"], 60)
        self.assertEqual(removal["status"], "removed")
        self.assertGreaterEqual(removal["duration_seconds"], 0)
        self.assertLessEqual(removal["duration_seconds"], receipt["duration_seconds"])
        self.assertTrue(receipt["cleanup"]["complete"])
        self.assertFalse(Path(receipt["ephemeral_root"]).exists())

    def test_cleanup_deadline_expiry_stays_failed_with_budget_and_timing(self):
        timer_log = self.base / "cleanup-timer.json"
        injection = (
            "import json, signal, shutil\nfrom pathlib import Path\n"
            "real_timer = signal.setitimer\nreal_remove = shutil.rmtree\n"
            "def accelerated_timer(which, seconds, interval=0):\n"
            "    if seconds > 0:\n"
            "        Path(" + repr(str(timer_log)) + ").write_text(json.dumps(seconds))\n"
            "        return real_timer(which, 0.02, interval)\n"
            "    return real_timer(which, seconds, interval)\n"
            "def blocked_remove(path, *args, **kwargs):\n"
            '    if "pkcs11-mutation-panel-" in str(path): signal.pause()\n'
            "    return real_remove(path, *args, **kwargs)\n"
            "signal.setitimer = accelerated_timer\nshutil.rmtree = blocked_remove\n"
        )
        self.output.write_text('{"status":"passed","prior_run":"sentinel"}\n')
        receipt = self.assert_failed("killed", "cleanup timeout", injection=injection)
        self.addCleanup(shutil.rmtree, receipt["ephemeral_root"], ignore_errors=True)
        self.assertEqual(json.loads(timer_log.read_text()), 60)
        self.assertEqual(receipt["counts"]["killed"], 1)
        self.assertFalse(receipt["cleanup"]["complete"])
        self.assertFalse(receipt["cleanup"]["ephemeral_root_removed"])
        self.assertTrue(all(command["cleanup_complete"] for command in receipt["commands"]))
        self.assertIn("ephemeral_removal", receipt["cleanup"])
        removal = receipt["cleanup"]["ephemeral_removal"]
        self.assertEqual(removal["budget_seconds"], 60)
        self.assertEqual(removal["status"], "failed")
        self.assertGreater(removal["duration_seconds"], 0)
        self.assertLessEqual(removal["duration_seconds"], receipt["duration_seconds"])

    def test_output_inside_source_refuses_without_overwriting_source(self):
        source = self.repo / SOURCE
        original = identity(source)
        self.output = source
        self.assertTrue(SCRIPT.is_file(), "mutation panel entrypoint must exist")
        shutil.copy2(SCRIPT, self.repo / "scripts/run-mutation-panel.py")
        result = subprocess.run(
            [
                sys.executable,
                str(self.repo / "scripts/run-mutation-panel.py"),
                "--output",
                str(source),
            ],
            text=True,
            capture_output=True,
            timeout=5,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(identity(source), original)
        self.assertIn("outside", result.stderr)


if __name__ == "__main__":
    unittest.main()
