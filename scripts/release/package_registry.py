"""Fail-closed crates.io identity and publication checks."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .package_model import EDGES, INTERNAL, PACKAGES, ReleaseError, require


HEX64 = re.compile(r"[0-9a-f]{64}\Z")
USER_AGENT = "pkcs11-proxy-ng-release-checks/0.2 (+https://github.com/mingulov/pkcs11-proxy-ng)"


def read_inventory(path: Path) -> dict:
    try:
        inventory = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise ReleaseError(f"cannot read candidate inventory {path}: {exc}") from exc
    require(isinstance(inventory, dict) and inventory.get("format_version") == 1,
            "candidate inventory format is invalid")
    require(isinstance(inventory.get("source_commit"), str) and
            re.fullmatch(r"[0-9a-f]{40}", inventory["source_commit"]) is not None,
            "candidate inventory source commit is invalid")
    version = inventory.get("version")
    records = inventory.get("packages")
    require(isinstance(version, str) and bool(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)),
            "candidate inventory version is invalid")
    require(isinstance(records, list) and len(records) == len(PACKAGES),
            "candidate inventory must contain eight packages")
    require([record.get("name") for record in records if isinstance(record, dict)] ==
            [name for name, _ in PACKAGES], "candidate inventory package order or names differ")
    for record in records:
        name = record["name"]
        require(record.get("version") == version and
                record.get("archive") == f"{name}-{version}.crate" and
                isinstance(record.get("sha256"), str) and
                HEX64.fullmatch(record["sha256"]) is not None,
                f"{name} candidate inventory identity invalid")
    return inventory


def _request(url: str) -> tuple[int, bytes]:
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urlopen(request, timeout=15) as response:
            return response.status, response.read(72 * 1024 * 1024 + 1)
    except HTTPError as exc:
        return exc.code, exc.read(1024)
    except (URLError, TimeoutError, OSError) as exc:
        raise OSError(f"registry request failed for {url}: {exc}") from exc


class Registry:
    def __init__(self, transport=None, *, pace=True, attempts=3):
        self.transport = transport or _request
        self.pace = pace
        self.attempts = attempts
        self.last_request = 0.0

    @staticmethod
    def metadata_url(name: str, version: str) -> str:
        return f"https://crates.io/api/v1/crates/{name}/{version}"

    @staticmethod
    def index_url(name: str) -> str:
        if len(name) == 1:
            suffix = "1/" + name
        elif len(name) == 2:
            suffix = "2/" + name
        elif len(name) == 3:
            suffix = "3/" + name[0] + "/" + name
        else:
            suffix = name[:2] + "/" + name[2:4] + "/" + name
        return "https://index.crates.io/" + suffix

    @staticmethod
    def download_url(name: str, version: str) -> str:
        return f"https://static.crates.io/crates/{name}/{name}-{version}.crate"

    def get(self, url: str) -> tuple[int, bytes]:
        for attempt in range(self.attempts):
            if self.pace:
                remaining = 1.0 - (time.monotonic() - self.last_request)
                if remaining > 0:
                    time.sleep(remaining)
                self.last_request = time.monotonic()
            try:
                status, data = self.transport(url)
            except (OSError, TimeoutError) as exc:
                if attempt + 1 == self.attempts:
                    raise ReleaseError(f"registry network failure at {url}: {exc}") from exc
                continue
            if status in (429, 500, 502, 503, 504) and attempt + 1 < self.attempts:
                continue
            require(status in (200, 404), f"registry HTTP {status} at {url}")
            require(len(data) <= 72 * 1024 * 1024, f"registry response too large at {url}")
            return status, data
        raise ReleaseError(f"registry retries exhausted at {url}")

    def lookup(self, name: str, version: str, expected: str | None = None) -> tuple[str, str | None]:
        for attempt in range(self.attempts):
            api_status, api_data = self.get(self.metadata_url(name, version))
            index_status, index_data = self.get(self.index_url(name))
            api_entry = None
            index_entry = None
            if api_status == 200:
                try:
                    api_entry = json.loads(api_data)["version"]
                except (ValueError, KeyError, TypeError) as exc:
                    raise ReleaseError(f"{name} invalid registry metadata: {exc}") from exc
                require(isinstance(api_entry, dict) and api_entry.get("num") == version,
                        f"{name} ambiguous registry metadata version")
            if index_status == 200:
                try:
                    versions = [json.loads(line) for line in index_data.splitlines() if line]
                except (ValueError, TypeError) as exc:
                    raise ReleaseError(f"{name} invalid sparse index: {exc}") from exc
                require(all(isinstance(entry, dict) for entry in versions),
                        f"{name} sparse index contains invalid records")
                matches = [entry for entry in versions if entry.get("vers") == version]
                require(len(matches) <= 1, f"{name} ambiguous sparse-index version")
                index_entry = matches[0] if matches else None
                if index_entry is not None:
                    require(index_entry.get("name") == name,
                            f"{name} sparse-index package name differs")
            for label, entry, field in (("metadata", api_entry, "checksum"),
                                        ("index", index_entry, "cksum")):
                if entry is not None:
                    require(entry.get("yanked") is False, f"{name} {label} version is yanked or ambiguous")
                    digest = entry.get(field)
                    require(isinstance(digest, str) and HEX64.fullmatch(digest) is not None,
                            f"{name} {label} checksum invalid")
                    if expected is not None:
                        require(digest == expected, f"{name} {label} checksum differs from candidate")
            if api_entry is None and index_entry is None:
                return "absent", None
            if api_entry is not None and index_entry is not None:
                require(api_entry["checksum"] == index_entry["cksum"],
                        f"{name} metadata and index checksums differ")
                return "published", index_entry["cksum"]
            if attempt + 1 < self.attempts and self.pace:
                time.sleep(1)
        raise ReleaseError(f"{name} registry API/index pending after bounded polling")

    def download(self, name: str, version: str, expected: str) -> bytes:
        status, data = self.get(self.download_url(name, version))
        require(status == 200, f"{name} published source download absent")
        require(hashlib.sha256(data).hexdigest() == expected,
                f"{name} downloaded archive checksum differs from candidate")
        return data


def _classify(inventory: dict, registry: Registry) -> dict[str, str]:
    states = {}
    for record in inventory["packages"]:
        name = record["name"]
        state, digest = registry.lookup(name, inventory["version"], record["sha256"])
        if state == "published":
            require(digest == record["sha256"], f"{name} registry checksum differs from candidate")
        states[name] = state
    return states


def publication_state(inventory: dict, selected: str, registry: Registry) -> dict:
    require(selected == "workspace" or selected in INTERNAL, f"unknown release package: {selected}")
    states = _classify(inventory, registry)
    if selected == "workspace":
        require(all(state == "absent" for state in states.values()),
                "workspace upload refused: one or more candidate packages already published")
    else:
        require(states[selected] == "absent", f"{selected} already published")
        directory = dict(PACKAGES)[selected]
        for dependency in EDGES[directory]:
            require(states[dependency] == "published",
                    f"{selected} dependency {dependency} is not indexed")
    return {"state": "ready", "selected": selected, "packages": states}


def verify_publication(inventory: dict, registry: Registry, *, selected: str | None = None) -> dict:
    require(selected is None or selected in INTERNAL, f"unknown release package: {selected}")
    states = _classify(inventory, registry)
    if selected is not None:
        require(states[selected] == "published", f"{selected} selected upload is not indexed")
    for record in inventory["packages"]:
        if states[record["name"]] == "published":
            registry.download(record["name"], inventory["version"], record["sha256"])
    missing = [name for name, state in states.items() if state == "absent"]
    if missing:
        require(selected is not None,
                f"publication incomplete without selected upload: {', '.join(missing)}")
    return {"state": "incomplete" if missing else "complete", "missing": missing,
            "packages": states}
