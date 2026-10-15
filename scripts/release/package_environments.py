"""Read-only GitHub Environments protection readback for release gates.

Consumes captured Environments API JSON (the list-environment payload
plus per-environment deployment-branch-policy payloads) and returns a
fail-closed verdict: a missing environment, an absent reviewer rule, a
malformed reviewer entry, a permissive, contradictory, or mismatched
ref policy, a truncated policy capture, or an unavailable/unrecognized
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

# Reviewer object types the Environments API returns for a
# required_reviewers rule; anything else refuses.
REVIEWER_TYPES = ("User", "Team")

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
    malformed reviewer entry, permissive, contradictory, or mismatched
    ref policy, truncated policy capture, or an unrecognized readback.
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
        rules = entry.get("protection_rules", [])
        require(isinstance(rules, list),
                f"environment {name!r} protection_rules readback is "
                "malformed (expected a list); refusing")
        reviewer_rules = []
        for rule in rules:
            require(isinstance(rule, dict),
                    f"environment {name!r} protection_rules readback "
                    "holds a malformed rule; refusing")
            if rule.get("type") == "required_reviewers":
                reviewer_rules.append(rule)
        require(reviewer_rules,
                f"environment {name!r} has no required-reviewers rule; refusing")
        for rule in reviewer_rules:
            reviewers = rule.get("reviewers")
            require(isinstance(reviewers, list),
                    f"environment {name!r} required-reviewers rule holds "
                    "a malformed reviewer list; refusing")
            require(len(reviewers) >= REQUIRED_REVIEWERS_MINIMUM,
                    f"environment {name!r} required-reviewers rule lists "
                    "no reviewers; refusing")
            for reviewer in reviewers:
                require(is_valid_reviewer(reviewer),
                        f"environment {name!r} required-reviewers rule holds "
                        "a malformed reviewer entry; refusing")
        policy = entry.get("deployment_branch_policy")
        require(isinstance(policy, dict),
                f"environment {name!r} has no deployment restriction "
                "(permissive); refusing")
        protected = policy.get("protected_branches")
        custom = policy.get("custom_branch_policies")
        require(isinstance(protected, bool) and isinstance(custom, bool),
                f"environment {name!r} deployment_branch_policy is malformed "
                "(protected_branches and custom_branch_policies must both "
                "be booleans); refusing")
        require((protected, custom) != (True, True),
                f"environment {name!r} has a contradictory "
                "deployment_branch_policy (protected_branches and "
                "custom_branch_policies are both true); refusing")
        require((protected, custom) != (False, False),
                f"environment {name!r} has no deployment restriction "
                "(permissive); refusing")
        expected = EXPECTED_POLICIES[name]
        if custom:
            require(name in policies_payloads,
                    f"environment {name!r} enables custom ref policies but no policy "
                    "readback was supplied; refusing")
            actual = read_policy_entries(policies_payloads[name], name)
            require(actual == set(expected),
                    f"environment {name!r} ref policy mismatch: expected "
                    f"{sorted(expected)}, got {sorted(actual)}; refusing")
        else:
            require(not expected,
                    f"environment {name!r} uses protected-branches-only instead of the "
                    f"documented selected-ref policy {sorted(expected)}; refusing")
    return tuple(environments)


def _is_nonblank_handle(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_positive_id(value: Any) -> bool:
    return (isinstance(value, int) and
            not isinstance(value, bool) and value > 0)


def is_valid_reviewer(reviewer: Any) -> bool:
    """Check one required_reviewers entry against the recognized shape.

    The API returns ``{"type": "User"|"Team", "reviewer": {...}}``
    objects. A User is identified by a non-blank ``login`` or a
    positive integer ``id``; a Team by a non-blank ``slug`` or a
    positive integer ``id``. The display ``name`` never counts as
    an identifier, and a present-but-invalid handle or id refuses
    even when the other identifier is valid.
    """
    if not isinstance(reviewer, dict):
        return False
    reviewer_type = reviewer.get("type")
    if reviewer_type not in REVIEWER_TYPES:
        return False
    identity = reviewer.get("reviewer")
    if not isinstance(identity, dict):
        return False
    handle_key = "login" if reviewer_type == "User" else "slug"
    if handle_key in identity and not _is_nonblank_handle(
            identity[handle_key]):
        return False
    if "id" in identity and not _is_positive_id(identity["id"]):
        return False
    return (_is_nonblank_handle(identity.get(handle_key)) or
            _is_positive_id(identity.get("id")))


def read_policy_entries(policies_payload: Any,
                        environment: str) -> set[tuple[str, str]]:
    """Collect the (type, name) entries of one captured policy readback.

    Read-only/offline: consumes captured list-deployment-branch-policies
    JSON. Refuses truncated captures (total_count disagreeing with the
    captured entries) with the environment and endpoint named instead
    of fetching further pages.
    """
    endpoint = "list-deployment-branch-policies"
    require(isinstance(policies_payload, dict) and
            isinstance(policies_payload.get("branch_policies"), list),
            f"environment {environment!r} deployment-branch-policy readback "
            f"unavailable or unrecognized ({endpoint}): expected a mapping "
            "with a branch_policies list")
    captured = policies_payload["branch_policies"]
    total = policies_payload.get("total_count")
    require(isinstance(total, int) and not isinstance(total, bool),
            f"environment {environment!r} deployment-branch-policy readback "
            f"is missing total_count ({endpoint}); refusing")
    require(total == len(captured),
            f"environment {environment!r} deployment-branch-policy readback "
            f"is incomplete ({endpoint}: total_count={total} but "
            f"{len(captured)} entries captured); re-capture every page; "
            "refusing")
    entries = set()
    for item in captured:
        require(isinstance(item, dict) and isinstance(item.get("type"), str) and
                isinstance(item.get("name"), str),
                f"environment {environment!r} deployment-branch-policy "
                "readback holds a nameless entry; refusing")
        entries.add((item["type"], item["name"]))
    require(entries,
            f"environment {environment!r} deployment-branch-policy readback "
            "holds no entries; refusing")
    return entries
