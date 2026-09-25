"""Create a private, allowlisted pkcs11-proxy-ng diagnostic bundle."""

from __future__ import annotations

import gzip
import os
import platform
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Callable, Dict, Iterable, Iterator, Mapping, Optional, Sequence, Tuple

ARCHIVE_FILES = (
    "artifacts.txt",
    "environment.txt",
    "manifest.txt",
    "providers.txt",
    "system.txt",
    "toolchain.txt",
    "workspace.txt",
)
ENVIRONMENT_NAMES = (
    "PKCS11_PROXY_ENDPOINT",
    "PKCS11_PROXY_SOCKET",
    "PKCS11_PROXY_TLS_CA_CERT",
    "PKCS11_PROXY_TLS_CLIENT_CERT",
    "PKCS11_PROXY_TLS_CLIENT_KEY",
    "PKCS11_PROXY_TLS_DOMAIN",
    "PKCS11_PROXY_BACKEND_MODULE",
    "PKCS11_PROXY_MECHANISMS_CONFIG",
    "SOFTHSM2_CONF",
    "CARGO_TARGET_DIR",
    "RUST_BACKTRACE",
)
KNOWN_KERNELS = {"Linux", "FreeBSD", "Darwin"}
KNOWN_MACHINES = {
    "x86_64",
    "amd64",
    "i386",
    "i486",
    "i586",
    "i686",
    "aarch64",
    "arm64",
    "riscv64",
    "s390x",
    "ppc64le",
}
VERSION_COMMANDS = (
    ("rustc", ("rustc", "--version"), re.compile(r"^rustc ([0-9]+\.[0-9]+\.[0-9]+)(?:\s|$)")),
    ("cargo", ("cargo", "--version"), re.compile(r"^cargo ([0-9]+\.[0-9]+\.[0-9]+)(?:\s|$)")),
    (
        "protoc",
        ("protoc", "--version"),
        re.compile(r"^(?:lib)?protoc ([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\s|$)"),
    ),
    (
        "pkg_config",
        ("pkg-config", "--version"),
        re.compile(r"^([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\s|$)"),
    ),
)


class CollectionError(Exception):
    """An expected, safely reportable collection failure."""


class CollectionInterrupted(CollectionError):
    """Collection was interrupted by a process-control signal."""

    def __init__(self, signal_number: int) -> None:
        super().__init__("collection interrupted")
        self.signal_number = signal_number


def _raise_interrupted(signal_number: int, _frame: object) -> None:
    raise CollectionInterrupted(signal_number)


def _install_signal_handlers() -> None:
    for signal_name in ("SIGHUP", "SIGINT", "SIGTERM"):
        signal_number = getattr(signal, signal_name, None)
        if signal_number is not None:
            signal.signal(signal_number, _raise_interrupted)


@contextmanager
def _defer_handled_signals() -> Iterator[None]:
    handled_signals = {
        signal_number
        for signal_name in ("SIGHUP", "SIGINT", "SIGTERM")
        if (signal_number := getattr(signal, signal_name, None)) is not None
    }
    try:
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, handled_signals)
    except (AttributeError, OSError):
        raise CollectionError("signal masking is unavailable") from None
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def _directory_open_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW


def _regular_create_flags() -> int:
    return os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW


@dataclass
class OutputDirectory:
    fd: int
    absolute_path: str
    identity: Tuple[int, int]

    @classmethod
    def open(cls, raw_path: str) -> "OutputDirectory":
        if not raw_path or any(
            ord(character) < 32 or ord(character) == 127 for character in raw_path
        ):
            raise CollectionError("unsafe output directory")
        raw_parts = Path(raw_path).parts
        if any(part in (".", "..") for part in raw_parts):
            raise CollectionError("unsafe output directory")

        absolute_path = os.path.abspath(raw_path)
        if absolute_path == os.path.sep:
            raise CollectionError("unsafe output directory")

        current_fd = os.open(os.path.sep, _directory_open_flags())
        try:
            for component in Path(absolute_path).parts[1:]:
                try:
                    next_fd = os.open(component, _directory_open_flags(), dir_fd=current_fd)
                except FileNotFoundError:
                    # A concurrent first run may have created it. Opening with
                    # O_NOFOLLOW below revalidates its type safely.
                    with suppress(FileExistsError):
                        os.mkdir(component, 0o700, dir_fd=current_fd)
                    next_fd = os.open(component, _directory_open_flags(), dir_fd=current_fd)
                os.close(current_fd)
                current_fd = next_fd

            details = os.fstat(current_fd)
            if details.st_uid != os.geteuid():
                raise CollectionError("output directory has the wrong owner")
            if stat.S_IMODE(details.st_mode) & 0o022:
                raise CollectionError("output directory is group or world writable")
            return cls(
                fd=current_fd,
                absolute_path=absolute_path,
                identity=(details.st_dev, details.st_ino),
            )
        except Exception:  # noqa: BLE001 - close the retained descriptor before re-raising
            os.close(current_fd)
            raise

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def path_still_names_open_directory(self) -> bool:
        try:
            details = os.stat(self.absolute_path, follow_symlinks=False)
        except OSError:
            return False
        return stat.S_ISDIR(details.st_mode) and (details.st_dev, details.st_ino) == self.identity

    def __enter__(self) -> "OutputDirectory":
        return self

    def __exit__(self, _kind: object, _value: object, _traceback: object) -> None:
        self.close()


@dataclass
class ReservedArchive:
    directory_fd: int
    fd: int
    name: str
    identity: Optional[Tuple[int, int]] = None

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def name_still_refers_to_created_inode(self) -> bool:
        identity = self.identity
        if identity is None and self.fd >= 0:
            try:
                descriptor_details = os.stat(self.fd)
            except OSError:
                return False
            if not stat.S_ISREG(descriptor_details.st_mode):
                return False
            identity = (descriptor_details.st_dev, descriptor_details.st_ino)
            self.identity = identity
        try:
            details = os.stat(self.name, dir_fd=self.directory_fd, follow_symlinks=False)
        except OSError:
            return False
        return (
            identity is not None
            and stat.S_ISREG(details.st_mode)
            and (details.st_dev, details.st_ino) == identity
        )

    def unlink_if_still_exact(self) -> None:
        if not self.name_still_refers_to_created_inode():
            return
        with suppress(FileNotFoundError):
            os.unlink(self.name, dir_fd=self.directory_fd)


def _reserve_archive(
    directory_fd: int,
    timestamp: str,
    token_factory: Callable[[int], str] = secrets.token_hex,
) -> ReservedArchive:
    for _attempt in range(128):
        token = token_factory(8)
        if not re.fullmatch(r"[0-9A-Za-z_-]{8,64}", token):
            raise CollectionError("invalid archive token")
        name = f"debug-bundle-{timestamp}-{token}.tar.gz"
        reserved = ReservedArchive(directory_fd=directory_fd, fd=-1, name=name)
        try:
            with _defer_handled_signals():
                try:
                    reserved.fd = os.open(
                        name,
                        _regular_create_flags(),
                        0o600,
                        dir_fd=directory_fd,
                    )
                except FileExistsError:
                    continue
                os.fchmod(reserved.fd, 0o600)
                details = os.fstat(reserved.fd)
                reserved.identity = (details.st_dev, details.st_ino)
            return reserved
        except BaseException:  # noqa: BLE001 - cleanup must also cover interruption
            try:
                reserved.unlink_if_still_exact()
            finally:
                reserved.close()
            raise
    raise CollectionError("cannot reserve unique archive name")


def _tar_info(name: str, mode: int, type_: bytes, size: int = 0) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = type_
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.size = size
    return info


def _write_archive(archive_fd: int, root_name: str, files: Mapping[str, bytes]) -> None:
    if tuple(sorted(files)) != ARCHIVE_FILES:
        raise CollectionError("archive allowlist mismatch")
    raw_fd = os.dup(archive_fd)
    with os.fdopen(raw_fd, "wb") as raw_file:  # noqa: SIM117 - keep Python 3.9 syntax
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_file, mtime=0) as gzip_file:
            with tarfile.open(fileobj=gzip_file, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
                archive.addfile(_tar_info(root_name, 0o700, tarfile.DIRTYPE))
                for filename in ARCHIVE_FILES:
                    content = files[filename]
                    member_name = f"{root_name}/{filename}"
                    archive.addfile(
                        _tar_info(member_name, 0o600, tarfile.REGTYPE, len(content)),
                        BytesIO(content),
                    )
    os.fsync(archive_fd)


def _run_command(arguments: Sequence[str], cwd: Optional[Path] = None) -> Optional[str]:
    environment = {"PATH": os.environ.get("PATH", ""), "LC_ALL": "C"}
    try:
        result = subprocess.run(
            arguments,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.splitlines()[0] if result.stdout else ""


def _normalized_versions() -> Dict[str, str]:
    versions: Dict[str, str] = {}
    for label, command, pattern in VERSION_COMMANDS:
        output = _run_command(command)
        match = pattern.match(output) if output is not None else None
        versions[label] = match.group(1) if match else "unavailable"
    return versions


def _git_fields(workspace_root: Path) -> Tuple[str, str]:
    head = _run_command(("git", "-C", str(workspace_root), "rev-parse", "--verify", "HEAD"))
    if head is None or re.fullmatch(r"[0-9a-fA-F]{40,64}", head) is None:
        return "unavailable", "unavailable"

    tracked_clean = _run_command(
        ("git", "-C", str(workspace_root), "diff-index", "--quiet", "HEAD", "--")
    )
    untracked = _run_command(
        ("git", "-C", str(workspace_root), "ls-files", "--others", "--exclude-standard")
    )
    dirty = tracked_clean is None or untracked is None or bool(untracked)
    return head.lower(), "true" if dirty else "false"


def _path_state(path: Path) -> str:
    try:
        details = path.lstat()
    except OSError:
        return "absent"
    return "present" if stat.S_ISREG(details.st_mode) else "absent"


def _section(label: str, values: Iterable[str]) -> bytes:
    return (f"=== {label} ===\n" + "\n".join(values) + "\n\n").encode("utf-8")


def _collect_files(workspace_root: Path) -> Dict[str, bytes]:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    kernel = platform.system()
    machine = platform.machine()
    cpu_count = os.cpu_count()
    versions = _normalized_versions()
    git_head, git_dirty = _git_fields(workspace_root)

    system = _section(
        "Allowlisted system fields",
        (
            f"utc={now}",
            f"kernel={kernel if kernel in KNOWN_KERNELS else 'other'}",
            f"architecture={machine if machine in KNOWN_MACHINES else 'other'}",
            "logical_cpus="
            f"{cpu_count if isinstance(cpu_count, int) and cpu_count > 0 else 'unavailable'}",
        ),
    )
    toolchain = _section(
        "Normalized tool versions",
        (f"{label}={versions[label]}" for label, _command, _pattern in VERSION_COMMANDS),
    )
    workspace = _section(
        "Allowlisted workspace fields",
        (f"git_head={git_head}", f"git_dirty={git_dirty}"),
    )
    providers = _section(
        "Known provider availability",
        (
            f"softhsm2={_path_state(Path('/usr/lib/softhsm/libsofthsm2.so'))}",
            "softhsm2_multiarch="
            f"{_path_state(Path('/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so'))}",
            f"nss_softokn={_path_state(Path('/usr/lib/x86_64-linux-gnu/nss/libsoftokn3.so'))}",
            f"kryoptic={_path_state(Path('/opt/kryoptic/target/release/libkryoptic_pkcs11.so'))}",
            f"pkcs11_tool={'available' if shutil.which('pkcs11-tool') else 'unavailable'}",
            f"p11tool={'available' if shutil.which('p11tool') else 'unavailable'}",
            f"openssl={'available' if shutil.which('openssl') else 'unavailable'}",
        ),
    )
    environment = _section(
        "Allowlisted environment presence",
        tuple(f"{name}={'set' if name in os.environ else 'unset'}" for name in ENVIRONMENT_NAMES)
        + ("Values are intentionally omitted. Unlisted variable names are not inspected.",),
    )
    artifacts = _section(
        "Workspace artifact presence",
        (
            f"daemon_debug={_path_state(workspace_root / 'target/debug/pkcs11-proxy-ng')}",
            f"daemon_release={_path_state(workspace_root / 'target/release/pkcs11-proxy-ng')}",
            f"shim_debug={_path_state(workspace_root / 'target/debug/libpkcs11_proxy_ng_shim.so')}",
            "shim_release="
            f"{_path_state(workspace_root / 'target/release/libpkcs11_proxy_ng_shim.so')}",
        ),
    )
    manifest = _section(
        "Diagnostic bundle contract",
        (
            "schema=1",
            "classification=diagnostic",
            "content=allowlisted-metadata-only",
            "raw_logs=excluded",
            "configuration_files=excluded",
            "environment_values=excluded",
            "command_errors=excluded",
            "sharing=review-required",
        ),
    )
    return {
        "artifacts.txt": artifacts,
        "environment.txt": environment,
        "manifest.txt": manifest,
        "providers.txt": providers,
        "system.txt": system,
        "toolchain.txt": toolchain,
        "workspace.txt": workspace,
    }


def _create_archive(
    output: OutputDirectory,
    files: Mapping[str, bytes],
    writer: Callable[[int, str, Mapping[str, bytes]], None] = _write_archive,
    token_factory: Callable[[int], str] = secrets.token_hex,
) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    reserved: Optional[ReservedArchive] = None
    try:
        # The outer mask closes the return-to-assignment signal window. The
        # nested reservation mask restores to this blocked state, then this
        # assignment establishes cleanup ownership before signals are handled.
        with _defer_handled_signals():
            reserved = _reserve_archive(output.fd, timestamp, token_factory)
        root_name = reserved.name.removesuffix(".tar.gz")
        writer(reserved.fd, root_name, files)
        if not reserved.name_still_refers_to_created_inode():
            raise CollectionError("archive path changed during collection")
        if not output.path_still_names_open_directory():
            raise CollectionError("output directory changed during collection")
        reserved.close()
        return reserved.name
    except BaseException:  # noqa: BLE001 - cleanup must also cover interruption
        if reserved is not None:
            try:
                reserved.unlink_if_still_exact()
            finally:
                reserved.close()
        raise


def _usage() -> str:
    return """Usage: scripts/collect-debug-bundle.sh [options]

Options:
  --output-dir DIR       Write bundle to DIR (default: target/debug-bundles/)
  -h, --help             Show this help

The bundle contains allowlisted system, toolchain, workspace, provider, and
artifact metadata. Raw logs, configuration files, and environment values are
never included. Review the archive before sharing it.
"""


def _parse_arguments(arguments: Sequence[str], workspace_root: Path) -> Optional[str]:
    output_directory = str(workspace_root / "target/debug-bundles")
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--output-dir":
            if index + 1 >= len(arguments):
                raise CollectionError("missing output directory")
            candidate = arguments[index + 1]
            if candidate.startswith("-"):
                raise CollectionError("missing output directory")
            output_directory = candidate
            index += 2
        elif argument == "--include-logs":
            raise CollectionError("raw log collection is unsupported")
        elif argument in ("-h", "--help"):
            return None
        else:
            raise CollectionError("unknown option")
    return output_directory


def main(arguments: Sequence[str]) -> int:
    workspace_root = Path(__file__).resolve().parents[1]
    try:
        output_path = _parse_arguments(arguments, workspace_root)
        if output_path is None:
            sys.stdout.write(_usage())
            return 0
        os.umask(0o077)
        _install_signal_handlers()
        with OutputDirectory.open(output_path) as output:
            files = _collect_files(workspace_root)
            archive_name = _create_archive(output, files)
            archive_path = os.path.join(output.absolute_path, archive_name)
        sys.stdout.write(f"[debug-bundle] Bundle created: {archive_path}\n")
        return 0
    except CollectionInterrupted as error:
        sys.stderr.write("[debug-bundle] collection interrupted\n")
        return 128 + error.signal_number
    except (CollectionError, OSError, ValueError, tarfile.TarError, gzip.BadGzipFile):
        sys.stderr.write("[debug-bundle] collection failed\n")
        return 1
    except Exception:  # noqa: BLE001 - never expose arbitrary diagnostic exception text
        # Diagnostic tooling must not echo arbitrary exception text: command
        # errors and paths may themselves contain sensitive material.
        sys.stderr.write("[debug-bundle] collection failed\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
