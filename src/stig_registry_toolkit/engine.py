"""Verify and fix checks against a registry backend.

Verification is pure comparison: read the value, compare its type and
content with the check's expectation. Fixing always verifies first,
records the prior value in a backup store, writes, then re-verifies.
A fix that does not re-verify as passing is reported as failed, never
as silently applied.

Contract: callers pass checks that have already been validated by
``checks.check_from_dict`` (the bundled loader validates every check
at load time). The ``assert`` statements below encode that contract;
they are not input validation for untrusted data.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

from .backup import BackupStore, PriorState, capture_prior
from .checks import Check
from .registry import (
    RegistryBackend,
    RegistryError,
    RegistryNotFoundError,
    coerce_value,
)

Status = Literal["pass", "fail", "manual", "error"]


@dataclass(frozen=True)
class CheckResult:
    check: Check
    status: Status
    detail: str
    actual: Any = None
    actual_type: str | None = None


@dataclass(frozen=True)
class FixOutcome:
    result: CheckResult
    changed: bool
    detail: str
    backup_recorded: bool = False


def can_auto_fix(check: Check) -> bool:
    """True when ``fix_check`` would actually write for this check.

    Manual checks have no target and pattern checks have no single
    value to write, so neither is ever auto-fixed. Every caller that
    previews, counts, or lists "fixable" checks must use this one
    definition, or previews and real runs disagree about what a fix
    will do.
    """
    return check.is_automated and check.pattern is None


def _compare(check: Check, actual: Any, actual_type: str) -> CheckResult:
    assert check.reg_type is not None
    expected_type = check.reg_type.upper()
    if actual_type.upper() != expected_type:
        return CheckResult(
            check,
            "fail",
            f"type mismatch: expected {expected_type}, got {actual_type}",
            actual,
            actual_type,
        )
    if check.pattern is not None:
        # Patterns are searched, not full-matched: anchors in the
        # pattern (for example "^https") do the restricting, so a
        # pattern without anchors matches a substring by design.
        text = actual if isinstance(actual, str) else str(actual)
        if re.search(check.pattern, text):
            return CheckResult(
                check,
                "pass",
                f"value matches pattern {check.pattern!r}",
                actual,
                actual_type,
            )
        return CheckResult(
            check,
            "fail",
            f"value {text!r} does not match pattern {check.pattern!r}",
            actual,
            actual_type,
        )
    expected = check.expected
    if isinstance(expected, list):
        allowed = [coerce_value(check.reg_type, item) for item in expected]
        if actual in allowed:
            return CheckResult(
                check,
                "pass",
                f"value {actual!r} is one of {allowed!r}",
                actual,
                actual_type,
            )
        return CheckResult(
            check,
            "fail",
            f"value {actual!r} is not one of {allowed!r}",
            actual,
            actual_type,
        )
    wanted = coerce_value(check.reg_type, expected)
    if actual == wanted:
        return CheckResult(
            check, "pass", f"value is {wanted!r} ({expected_type})", actual, actual_type
        )
    return CheckResult(
        check,
        "fail",
        f"value mismatch: expected {wanted!r}, got {actual!r}",
        actual,
        actual_type,
    )


def verify_check(check: Check, backend: RegistryBackend) -> CheckResult:
    """Verify one check. Manual checks are never auto-verified."""
    if not check.is_automated:
        return CheckResult(
            check, "manual", "Manual check: verify by hand; no registry target."
        )
    assert check.hive is not None and check.path is not None
    assert check.value_name is not None
    try:
        actual, actual_type = backend.read(check.hive, check.path, check.value_name)
    except RegistryNotFoundError:
        return CheckResult(
            check,
            "fail",
            f"{check.hive}\\{check.path}\\{check.value_name} does not exist",
        )
    except RegistryError as exc:
        return CheckResult(check, "error", str(exc))
    except Exception as exc:  # backend bugs must not crash a whole run
        return CheckResult(check, "error", f"unexpected error: {exc}")
    return _compare(check, actual, actual_type)


def verify_all(checks: list[Check], backend: RegistryBackend) -> list[CheckResult]:
    return [verify_check(check, backend) for check in checks]


def _fix_value(check: Check) -> Any:
    """The single value a fix writes, or None if the check has none."""
    if check.pattern is not None:
        return None
    expected = check.expected
    if isinstance(expected, list):
        # Any allowed value satisfies the check; use the first.
        return coerce_value(check.reg_type or "", expected[0])
    return coerce_value(check.reg_type or "", expected)


def fix_check(
    check: Check,
    backend: RegistryBackend,
    *,
    app: str,
    backup_store: BackupStore | None = None,
) -> FixOutcome:
    """Fix one check, recording its prior value first.

    Returns ``changed=False`` for checks that were already passing,
    manual, or not auto-fixable. Raises nothing for expected registry
    failures; those come back as failed outcomes.
    """
    if not check.is_automated:
        return FixOutcome(
            verify_check(check, backend),
            changed=False,
            detail="Manual check: not fixed automatically.",
        )
    if check.pattern is not None:
        return FixOutcome(
            verify_check(check, backend),
            changed=False,
            detail=(
                "Pattern check: no single expected value to write; "
                "set the value by hand."
            ),
        )
    current = verify_check(check, backend)
    if current.status == "pass":
        return FixOutcome(
            current, changed=False, detail="Already passing; nothing to do."
        )
    if current.status == "error":
        return FixOutcome(
            current,
            changed=False,
            detail=f"Not fixed: verification errored: {current.detail}",
        )
    assert check.hive is not None and check.path is not None
    assert check.value_name is not None and check.reg_type is not None
    prior: PriorState = capture_prior(backend, check)
    backup_recorded = False
    if backup_store is not None:
        backup_store.record(app, check, prior)
        backup_recorded = True
    try:
        backend.write(
            check.hive,
            check.path,
            check.value_name,
            check.reg_type,
            _fix_value(check),
            create_keys=True,
        )
    except RegistryError as exc:
        return FixOutcome(
            current,
            changed=False,
            detail=f"Write failed (prior value was backed up): {exc}",
            backup_recorded=backup_recorded,
        )
    except Exception as exc:
        return FixOutcome(
            current,
            changed=False,
            detail=f"Write failed unexpectedly (prior value was backed up): {exc}",
            backup_recorded=backup_recorded,
        )
    after = verify_check(check, backend)
    if after.status == "pass":
        return FixOutcome(
            after,
            changed=True,
            detail=f"Fixed and re-verified as passing. Prior state: {prior}.",
            backup_recorded=backup_recorded,
        )
    return FixOutcome(
        after,
        changed=False,
        detail=(
            "Write completed but re-verification did not pass; "
            "restore the recorded backup if needed. "
            f"Re-verification said: {after.detail}"
        ),
        backup_recorded=backup_recorded,
    )


def fix_all(
    checks: list[Check],
    backend: RegistryBackend,
    *,
    app: str,
    backup_store: BackupStore | None = None,
) -> list[FixOutcome]:
    """Fix every check, continuing past individual failures."""
    return [
        fix_check(check, backend, app=app, backup_store=backup_store)
        for check in checks
    ]
