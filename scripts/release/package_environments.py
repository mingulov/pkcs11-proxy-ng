"""Read-only GitHub Environments protection readback for release gates.

Consumes captured Environments API JSON (the list-environment payload
plus per-environment deployment-branch-policy payloads) and returns a
fail-closed verdict: a missing environment, an absent reviewer rule, a
permissive or mismatched ref policy, or an unavailable/unrecognized
readback refuses. This module never calls the network and never
mutates anything; callers fetch the readback with read-only ``gh api``
GETs (any account with repository read access) and pass the bytes in.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .package_model import ReleaseError, require


PRODUCTION_ENVIRONMENTS = ("release-tag", "crates-io", "release")
REQUIRED_REVIEWERS_MINIMUM = 1

# Intended deployment-branch-policy entries per production environment
# as (policy type, name pattern) pairs; the live readback must match
# exactly. Patterns use the API's fnmatch syntax (`*` never spans `/`).
EXPECTED_POLICIES = {
    "release-tag": (("branch", "main"),),
    "crates-io": (("tag", "v*"),),
    "release": (("tag", "v*"),),
}


def load_json(path: Path) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ReleaseError(f"cannot read {path}: {exc}") from exc
    except ValueError as exc:
        raise ReleaseError(f"cannot parse {path} as JSON: {exc}") from exc


def verify_environment_protections(
        environments_payload: Any,
        policies_payloads: dict[str, Any] | None = None,
        environments: tuple[str, ...] = PRODUCTION_ENVIRONMENTS,
) -> tuple[str, ...]:
    """Verify the protection contract for each named environment.

    Returns the verified names. Raises ReleaseError on any defect:
    unknown contract, missing environment, absent reviewer rule,
    permissive or mismatched ref policy, or an unrecognized readback.
    """
    require(isinstance(environments_payload, dict) and
            isinstance(environments_payload.get("environments"), list),
            "environments API readback unavailable or unrecognized: "
            "expected a mapping with an environments list")
    entries = {entry.get("name"): entry
               for entry in environments_payload["environments"]
               if isinstance(entry, dict)}
    policies_payloads = policies_payloads or {}
    for name in environments:
        require(name in EXPECTED_POLICIES,
                f"no documented protection contract for environment {name!r}; refusing")
        require(name in entries,
                f"environment {name!r} is missing from the environments "
                "readback; refusing")
        entry = entries[name]
        reviewers = [rule for rule in entry.get("protection_rules", [])
                     if isinstance(rule, dict) and
                     rule.get("type") == "required_reviewers" and
                     isinstance(rule.get("reviewers"), list) and
                     len(rule["reviewers"]) >= REQUIRED_REVIEWERS_MINIMUM]
        require(reviewers,
                f"environment {name!r} has no required-reviewers rule; refusing")
        policy = entry.get("deployment_branch_policy")
        require(isinstance(policy, dict) and
                (policy.get("protected_branches") is True or
                 policy.get("custom_branch_policies") is True),
                f"environment {name!r} has no deployment restriction "
                "(permissive); refusing")
        expected = EXPECTED_POLICIES[name]
        if policy.get("custom_branch_policies") is True:
            require(name in policies_payloads,
                    f"environment {name!r} enables custom ref policies but no policy "
                    "readback was supplied; refusing")
            actual = read_policy_entries(policies_payloads[name])
            require(actual == set(expected),
                    f"environment {name!r} ref policy mismatch: expected "
                    f"{sorted(expected)}, got {sorted(actual)}; refusing")
        else:
            require(not expected,
                    f"environment {name!r} uses protected-branches-only instead of the "
                    f"documented selected-ref policy {sorted(expected)}; refusing")
    return tuple(environments)


def read_policy_entries(policies_payload: Any) -> set[tuple[str, str]]:
    require(isinstance(policies_payload, dict) and
            isinstance(policies_payload.get("branch_policies"), list),
            "deployment-branch-policy readback unavailable or unrecognized: "
            "expected a mapping with a branch_policies list")
    entries = set()
    for item in policies_payload["branch_policies"]:
        require(isinstance(item, dict) and isinstance(item.get("type"), str) and
                isinstance(item.get("name"), str),
                "deployment-branch-policy readback holds a nameless entry; refusing")
        entries.add((item["type"], item["name"]))
    require(entries, "deployment-branch-policy readback holds no entries; refusing")
    return entries
