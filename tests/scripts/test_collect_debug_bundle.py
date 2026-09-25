"""Adversarial tests for the diagnostic bundle boundary."""

from __future__ import annotations

import importlib.util
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

SOURCE_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "collect-debug-bundle.sh"
SOURCE_HELPER = SOURCE_SCRIPT.parent / "collect_debug_bundle.py"


def load_helper():
    module_name = "collect_debug_bundle_under_test"
    spec = importlib.util.spec_from_file_location(module_name, SOURCE_HELPER)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load diagnostic bundle helper")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def open_fd_count() -> int:
    return len(list(Path("/proc/self/fd").iterdir()))


class DebugBundleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.workspace = self.root / "workspace"
        self.output = self.root / "output"
        (self.workspace / "scripts").mkdir(parents=True)
        self.output.mkdir()
        self.output.chmod(0o700)
        shutil.copy2(SOURCE_SCRIPT, self.workspace / "scripts" / SOURCE_SCRIPT.name)
        if SOURCE_HELPER.exists():
            shutil.copy2(SOURCE_HELPER, self.workspace / "scripts" / SOURCE_HELPER.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    @property
    def script(self) -> Path:
        return self.workspace / "scripts" / SOURCE_SCRIPT.name

    def run_collector(
        self,
        *args: str | os.PathLike[str],
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = [str(self.script), "--output-dir", str(self.output)]
        command.extend(os.fspath(arg) for arg in args)
        process_env = os.environ.copy()
        if env:
            process_env.update(env)
        return subprocess.run(
            command,
            cwd=self.workspace,
            env=process_env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def archives(self) -> list[Path]:
        return sorted(self.output.glob("debug-bundle-*.tar.gz"))

    def extract_and_read_files(
        self, archive: Path
    ) -> tuple[list[tarfile.TarInfo], dict[str, bytes]]:
        extraction = self.root / f"extracted-{archive.stem}"
        extraction.mkdir()
        with tarfile.open(archive, "r:gz") as bundle:
            members = bundle.getmembers()
            for member in members:
                self.assertFalse(member.issym() or member.islnk(), member.name)
                member_path = Path(member.name)
                self.assertFalse(member_path.is_absolute(), member.name)
                self.assertNotIn("..", member_path.parts, member.name)
            # Member paths and types are checked above. Use the hardened filter
            # where available while retaining Python 3.9 compatibility.
            try:
                bundle.extractall(extraction, filter="data")
            except TypeError:
                bundle.extractall(extraction)

        files: dict[str, bytes] = {}
        for path in extraction.rglob("*"):
            if path.is_file():
                files[path.relative_to(extraction).as_posix()] = path.read_bytes()
        return members, files

    def install_failing_command(self, name: str, canary: str) -> Path:
        fake_bin = self.root / "fake-bin"
        fake_bin.mkdir(exist_ok=True)
        command = fake_bin / name
        command.write_text(
            f"#!/bin/sh\nprintf '%s\\n' '{canary}'\nprintf '%s\\n' '{canary}' >&2\nexit 23\n",
            encoding="utf-8",
        )
        command.chmod(0o700)
        return fake_bin

    def install_successful_command(self, name: str, output: str) -> Path:
        fake_bin = self.root / "fake-bin"
        fake_bin.mkdir(exist_ok=True)
        command = fake_bin / name
        command.write_text(
            f"#!/bin/sh\nprintf '%s\\n' '{output}'\n",
            encoding="utf-8",
        )
        command.chmod(0o700)
        return fake_bin

    def test_archive_is_private_allowlisted_and_contains_no_canaries(self) -> None:
        env_canary = "ENV-CANARY-8bc3e21a"
        registry_canary = "REGISTRY-TOKEN-CANARY-9e4cbd32"
        config_canary = "CONFIG-CANARY-a4f6d8c0"
        command_canary = "COMMAND-ERROR-CANARY-c7e5319b"

        examples = self.workspace / "examples"
        examples.mkdir()
        (examples / "config.toml").write_text(
            f'initialize_args = "{config_canary}"\n', encoding="utf-8"
        )
        (self.workspace / "failure.log").write_text(env_canary, encoding="utf-8")
        fake_bin = self.install_failing_command("rustc", command_canary)
        self.install_failing_command("getconf", command_canary)

        result = self.run_collector(
            env={
                "PATH": f"{fake_bin}:{os.environ['PATH']}",
                "ARBITRARY_SECRET_NAME": env_canary,
                "CARGO_REGISTRIES_PRIVATE_TOKEN": registry_canary,
                "PKCS11_PROXY_ENDPOINT": f"https://user:{env_canary}@example.invalid",
                "PKCS11_PROXY_PIN": env_canary,
                "SOFTHSM2_CONF": f"/tmp/{env_canary}.conf",
            }
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(env_canary, result.stdout + result.stderr)
        self.assertNotIn(command_canary, result.stdout + result.stderr)

        [archive] = self.archives()
        self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o600)
        self.assertEqual(archive.stat().st_uid, os.geteuid())

        members, files = self.extract_and_read_files(archive)
        self.assertEqual(len(files), 7)
        self.assertEqual(len({Path(name).parent for name in files}), 1)
        file_basenames = {Path(name).name for name in files}
        self.assertEqual(
            file_basenames,
            {
                "artifacts.txt",
                "environment.txt",
                "manifest.txt",
                "providers.txt",
                "system.txt",
                "toolchain.txt",
                "workspace.txt",
            },
        )
        for member in members:
            expected_mode = 0o700 if member.isdir() else 0o600
            self.assertEqual(member.mode, expected_mode, member.name)
            self.assertEqual(member.uid, 0, member.name)
            self.assertEqual(member.gid, 0, member.name)
            self.assertEqual(member.uname, "", member.name)
            self.assertEqual(member.gname, "", member.name)
            self.assertEqual(member.mtime, 0, member.name)

        archived = b"\n".join(files.values())
        for canary in (env_canary, registry_canary, config_canary, command_canary):
            self.assertNotIn(canary.encode(), archived)

    def test_log_collection_option_is_rejected_without_reading_duplicate_or_symlinked_logs(
        self,
    ) -> None:
        log_canary = "LOG-CANARY-5be2d419"
        outside = self.root / "outside.log"
        outside.write_text(log_canary, encoding="utf-8")
        logs = self.root / "logs"
        (logs / "one").mkdir(parents=True)
        (logs / "two").mkdir()
        (logs / "one" / "duplicate.log").write_text(log_canary, encoding="utf-8")
        (logs / "two" / "duplicate.log").write_text(log_canary, encoding="utf-8")
        (logs / "outside.log").symlink_to(outside)

        result = self.run_collector("--include-logs", logs)

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.archives(), [])
        self.assertNotIn(log_canary, result.stdout + result.stderr)
        self.assertEqual(outside.read_text(encoding="utf-8"), log_canary)

    def test_symlink_output_directory_is_rejected_without_writing_outside_scope(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        self.output.rmdir()
        self.output.symlink_to(outside, target_is_directory=True)

        result = self.run_collector()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(outside.iterdir()), [])

    def test_symlink_parent_component_is_rejected_without_writing_outside_scope(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        parent_link = self.root / "parent-link"
        parent_link.symlink_to(outside, target_is_directory=True)
        self.output = parent_link / "nested"

        result = self.run_collector()

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((outside / "nested").exists())

    def test_non_directory_output_type_is_rejected_without_modification(self) -> None:
        self.output.rmdir()
        self.output.write_text("keep this file", encoding="utf-8")

        result = self.run_collector()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.output.read_text(encoding="utf-8"), "keep this file")

    def test_concurrent_runs_create_distinct_complete_archives(self) -> None:
        commands = [
            subprocess.Popen(
                [str(self.script), "--output-dir", str(self.output)],
                cwd=self.workspace,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for _ in range(6)
        ]
        results = [process.communicate(timeout=30) + (process.returncode,) for process in commands]

        for stdout, stderr, returncode in results:
            self.assertEqual(returncode, 0, stdout + stderr)
        archives = self.archives()
        self.assertEqual(len(archives), 6)
        self.assertEqual(len({archive.name for archive in archives}), 6)
        for archive in archives:
            with tarfile.open(archive, "r:gz") as bundle:
                self.assertTrue(bundle.getmembers())

    def test_concurrent_first_runs_create_missing_output_directory_safely(self) -> None:
        self.output.rmdir()
        commands = [
            subprocess.Popen(
                [str(self.script), "--output-dir", str(self.output)],
                cwd=self.workspace,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for _ in range(6)
        ]
        results = [process.communicate(timeout=30) + (process.returncode,) for process in commands]

        for stdout, stderr, returncode in results:
            self.assertEqual(returncode, 0, stdout + stderr)
        self.assertEqual(len(self.archives()), 6)

    def test_tar_and_gzip_environment_options_cannot_change_archive_shape_or_modes(self) -> None:
        result = self.run_collector(
            env={
                "TAR_OPTIONS": "--mode=0777 --transform=s,^,attacker-prefix/;",
                "GZIP": "-1 --name",
            }
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        [archive] = self.archives()
        raw = archive.read_bytes()
        self.assertEqual(raw[:2], b"\x1f\x8b")
        self.assertEqual(raw[3] & 0x08, 0, "gzip header must not contain an original filename")
        self.assertEqual(int.from_bytes(raw[4:8], "little"), 0, "gzip timestamp must be fixed")
        with tarfile.open(archive, "r:gz") as bundle:
            members = bundle.getmembers()
        self.assertEqual(len(members), 8)
        self.assertEqual(len({Path(member.name).parts[0] for member in members}), 1)
        self.assertTrue(members[0].isdir())
        for member in members[1:]:
            self.assertTrue(member.isreg(), member.name)
        for member in members:
            self.assertEqual(member.mode, 0o700 if member.isdir() else 0o600, member.name)

    def test_output_directory_swap_cannot_redirect_or_strand_bundle_files(self) -> None:
        ready = self.root / "ready"
        proceed = self.root / "proceed"
        fake_bin = self.root / "swap-bin"
        fake_bin.mkdir()
        rustc = fake_bin / "rustc"
        rustc.write_text(
            "#!/bin/sh\n"
            f": > '{ready}'\n"
            f"while [ ! -e '{proceed}' ]; do :; done\n"
            "printf '%s\\n' 'rustc 1.88.0'\n",
            encoding="utf-8",
        )
        rustc.chmod(0o700)
        process = subprocess.Popen(
            [str(self.script), "--output-dir", str(self.output)],
            cwd=self.workspace,
            env={**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + 10
        while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(ready.exists(), "collector did not reach the post-validation command")

        validated_directory = self.root / "validated-directory"
        outside = self.root / "outside"
        outside.mkdir()
        self.output.rename(validated_directory)
        self.output.symlink_to(outside, target_is_directory=True)
        proceed.touch()
        stdout, stderr = process.communicate(timeout=30)

        self.assertNotEqual(process.returncode, 0, stdout + stderr)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(list(validated_directory.iterdir()), [])

    def test_preexisting_reserved_archive_symlink_is_never_overwritten(self) -> None:
        helper = load_helper()
        outside = self.root / "outside-archive"
        outside.write_bytes(b"do not overwrite")
        timestamp = "20260913T120000Z"
        reserved = self.output / f"debug-bundle-{timestamp}-reserved.tar.gz"
        reserved.symlink_to(outside)
        tokens = iter(("reserved", "freshname"))

        with helper.OutputDirectory.open(str(self.output)) as output:
            archive = helper._reserve_archive(output.fd, timestamp, lambda _size: next(tokens))
            self.assertEqual(archive.name, f"debug-bundle-{timestamp}-freshname.tar.gz")
            archive.close()
            archive.unlink_if_still_exact()

        self.assertEqual(outside.read_bytes(), b"do not overwrite")
        self.assertTrue(reserved.is_symlink())

    def test_successful_tool_version_output_cannot_embed_suffix_canary(self) -> None:
        canary = "SUCCESS-VERSION-CANARY-7c4108f2"
        fake_bin = self.install_successful_command("rustc", f"rustc 1.88.0-{canary}")

        result = self.run_collector(env={"PATH": f"{fake_bin}:{os.environ['PATH']}"})

        self.assertEqual(result.returncode, 0, result.stderr)
        [archive] = self.archives()
        _, files = self.extract_and_read_files(archive)
        self.assertNotIn(canary.encode(), b"\n".join(files.values()))

    def test_collector_does_not_require_tar_gzip_or_mktemp_commands(self) -> None:
        minimal_bin = self.root / "minimal-bin"
        minimal_bin.mkdir()
        (minimal_bin / "bash").symlink_to(shutil.which("bash"))
        (minimal_bin / "python3").symlink_to(shutil.which("python3"))

        result = self.run_collector(env={"PATH": str(minimal_bin)})

        self.assertEqual(result.returncode, 0, result.stderr)
        [archive] = self.archives()
        with tarfile.open(archive, "r:gz") as bundle:
            self.assertEqual(len(bundle.getmembers()), 8)

    def test_group_writable_output_directory_is_rejected(self) -> None:
        self.output.chmod(0o770)

        result = self.run_collector()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_output_directory_option_cannot_consume_another_option_as_its_path(self) -> None:
        result = self.run_collector("--output-dir", "--help")

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.workspace / "--help").exists())

    def test_archive_failure_removes_exact_partial_output(self) -> None:
        helper = load_helper()
        neighbor = self.output / "keep.txt"
        neighbor.write_text("must survive", encoding="utf-8")

        def failing_writer(archive_fd, _root_name, _files):
            os.write(archive_fd, b"partial archive")
            raise RuntimeError("simulated writer failure")

        with (
            helper.OutputDirectory.open(str(self.output)) as output,
            self.assertRaisesRegex(RuntimeError, "simulated writer failure"),
        ):
            helper._create_archive(output, {}, writer=failing_writer)

        self.assertEqual(list(self.output.iterdir()), [neighbor])
        self.assertEqual(neighbor.read_text(encoding="utf-8"), "must survive")

    def test_failure_cleanup_does_not_unlink_replacement_inode(self) -> None:
        helper = load_helper()
        outside = self.root / "replacement-target"
        outside.write_text("must survive", encoding="utf-8")
        replacement_name = ""

        def replacing_writer(archive_fd, root_name, _files):
            nonlocal replacement_name
            replacement_name = f"{root_name}.tar.gz"
            os.write(archive_fd, b"partial archive")
            os.unlink(replacement_name, dir_fd=output.fd)
            os.symlink(outside, replacement_name, dir_fd=output.fd)
            raise RuntimeError("simulated replacement race")

        with (
            helper.OutputDirectory.open(str(self.output)) as output,
            self.assertRaisesRegex(RuntimeError, "simulated replacement race"),
        ):
            helper._create_archive(output, {}, writer=replacing_writer)

        replacement = self.output / replacement_name
        self.assertTrue(replacement.is_symlink())
        self.assertEqual(outside.read_text(encoding="utf-8"), "must survive")

    def test_interrupted_archive_writer_removes_its_partial_inode(self) -> None:
        helper = load_helper()

        def interrupted_writer(archive_fd, _root_name, _files):
            os.write(archive_fd, b"partial archive")
            raise KeyboardInterrupt

        with helper.OutputDirectory.open(str(self.output)) as output:  # noqa: SIM117
            with self.assertRaises(KeyboardInterrupt):
                helper._create_archive(output, {}, writer=interrupted_writer)

        self.assertEqual(list(self.output.iterdir()), [])

    def test_fchmod_failure_during_reservation_leaks_neither_file_nor_descriptor(self) -> None:
        helper = load_helper()
        neighbor = self.output / "keep.txt"
        neighbor.write_text("must survive", encoding="utf-8")

        with helper.OutputDirectory.open(str(self.output)) as output:
            descriptors_before = open_fd_count()
            with (
                mock.patch.object(helper.os, "fchmod", side_effect=OSError("injected fchmod")),
                self.assertRaises(OSError),
            ):
                helper._reserve_archive(output.fd, "20260913T120000Z")
            self.assertEqual(open_fd_count(), descriptors_before)

        self.assertEqual(list(self.output.iterdir()), [neighbor])
        self.assertEqual(neighbor.read_text(encoding="utf-8"), "must survive")

    def test_fstat_failure_during_reservation_leaks_neither_file_nor_descriptor(self) -> None:
        helper = load_helper()
        neighbor = self.output / "keep.txt"
        neighbor.write_text("must survive", encoding="utf-8")

        with helper.OutputDirectory.open(str(self.output)) as output:
            descriptors_before = open_fd_count()
            with (
                mock.patch.object(helper.os, "fstat", side_effect=OSError("injected fstat")),
                self.assertRaises(OSError),
            ):
                helper._reserve_archive(output.fd, "20260913T120000Z")
            self.assertEqual(open_fd_count(), descriptors_before)

        self.assertEqual(list(self.output.iterdir()), [neighbor])
        self.assertEqual(neighbor.read_text(encoding="utf-8"), "must survive")

    def test_sigterm_during_reservation_is_deferred_until_exact_cleanup_is_owned(self) -> None:
        helper = load_helper()
        neighbor = self.output / "keep.txt"
        neighbor.write_text("must survive", encoding="utf-8")
        handled_signals = [signal_name for signal_name in ("SIGHUP", "SIGINT", "SIGTERM")]
        previous_handlers = {
            signal_name: helper.signal.getsignal(getattr(helper.signal, signal_name))
            for signal_name in handled_signals
        }
        original_fchmod = helper.os.fchmod

        def interrupting_fchmod(archive_fd, mode):
            helper.os.kill(helper.os.getpid(), helper.signal.SIGTERM)
            original_fchmod(archive_fd, mode)

        helper._install_signal_handlers()
        try:
            with helper.OutputDirectory.open(str(self.output)) as output:
                descriptors_before = open_fd_count()
                with (
                    mock.patch.object(helper.os, "fchmod", side_effect=interrupting_fchmod),
                    self.assertRaises(helper.CollectionInterrupted),
                ):
                    helper._reserve_archive(output.fd, "20260913T120000Z")
                self.assertEqual(open_fd_count(), descriptors_before)
        finally:
            for signal_name, previous_handler in previous_handlers.items():
                helper.signal.signal(getattr(helper.signal, signal_name), previous_handler)

        self.assertEqual(list(self.output.iterdir()), [neighbor])
        self.assertEqual(neighbor.read_text(encoding="utf-8"), "must survive")

    def test_sigterm_at_reservation_return_is_caught_by_create_cleanup_scope(self) -> None:
        helper = load_helper()
        neighbor = self.output / "keep.txt"
        neighbor.write_text("must survive", encoding="utf-8")
        handled_signals = [signal_name for signal_name in ("SIGHUP", "SIGINT", "SIGTERM")]
        previous_handlers = {
            signal_name: helper.signal.getsignal(getattr(helper.signal, signal_name))
            for signal_name in handled_signals
        }
        original_reserve = helper._reserve_archive

        def interrupting_reserve(*args, **kwargs):
            reserved = original_reserve(*args, **kwargs)
            helper.os.kill(helper.os.getpid(), helper.signal.SIGTERM)
            return reserved

        helper._install_signal_handlers()
        try:
            with helper.OutputDirectory.open(str(self.output)) as output:
                descriptors_before = open_fd_count()
                with (
                    mock.patch.object(
                        helper,
                        "_reserve_archive",
                        side_effect=interrupting_reserve,
                    ),
                    self.assertRaises(helper.CollectionInterrupted),
                ):
                    helper._create_archive(output, {})
                self.assertEqual(open_fd_count(), descriptors_before)
        finally:
            for signal_name, previous_handler in previous_handlers.items():
                helper.signal.signal(getattr(helper.signal, signal_name), previous_handler)

        self.assertEqual(list(self.output.iterdir()), [neighbor])
        self.assertEqual(neighbor.read_text(encoding="utf-8"), "must survive")

    def test_matrix_failure_call_does_not_offer_raw_logs_to_collector(self) -> None:
        matrix = self.workspace / "scripts" / "test-matrix.sh"
        shutil.copy2(SOURCE_SCRIPT.parent / "test-matrix.sh", matrix)
        collector_args = self.workspace / "collector-args"
        self.script.write_text(
            '#!/bin/sh\n: > "$PWD/collector-args"\n'
            'for arg do printf \'%s\\n\' "$arg" >> "$PWD/collector-args"; done\n',
            encoding="utf-8",
        )
        self.script.chmod(0o700)
        fake_bin = self.root / "matrix-bin"
        fake_bin.mkdir()
        fake_cargo = fake_bin / "cargo"
        fake_cargo.write_text("#!/bin/sh\nexit 7\n", encoding="utf-8")
        fake_cargo.chmod(0o700)

        result = subprocess.run(
            [str(matrix), "--fast-only"],
            cwd=self.workspace,
            env={**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertEqual(result.returncode, 7, result.stdout + result.stderr)
        self.assertTrue(collector_args.exists())
        self.assertEqual(collector_args.read_text(encoding="utf-8"), "")


if __name__ == "__main__":
    unittest.main()
