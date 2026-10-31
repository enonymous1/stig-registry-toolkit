"""Canonical STIG check definitions.

The bundled data files carry no results. A check's status is always
computed live against the registry, so a shipped file can never claim a
machine is compliant because some other machine once passed.

Canonical schema (``schema_version`` 1)::

    {
      "schema_version": 1,
      "app": "Google Chrome",
      "checks": [
        {
          "id": "V-221558",
          "title": "...",
          "severity": "medium",
          "test_type": "automated",
          "description": "...",
          "fix_text": "...",
          "reference": null,
          "rule_id": null,
          "hive": "HKEY_LOCAL_MACHINE",
          "path": "SOFTWARE\\Policies\\Google\\Chrome",
          "value_name": "RemoteAccessHostFirewallTraversal",
          "reg_type": "REG_DWORD",
          "expected": 0,
          "pattern": null
        }
      ]
    }

``expected`` may be a scalar or a list of acceptable values (any-of).
``pattern`` is a regular expression the stored string must match; a
pattern check has no single value to write, so it cannot be auto-fixed.
Manual checks have no registry target at all.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .registry import REG_TYPE_NAMES, coerce_value

SCHEMA_VERSION = 1

APPS: dict[str, str] = {
    "chrome": "Google Chrome",
    "adobe": "Adobe Acrobat Reader DC",
}

# Friendly aliases accepted by the CLI and GUI.
APP_ALIASES: dict[str, str] = {
    "chrome": "chrome",
    "google-chrome": "chrome",
    "google_chrome": "chrome",
    "adobe": "adobe",
    "adobe-dc": "adobe",
    "adobe_dc": "adobe",
    "acrobat": "adobe",
}

CHECK_FIELDS = frozenset(
    {
        "id",
        "title",
        "severity",
        "test_type",
        "description",
        "fix_text",
        "reference",
        "rule_id",
        "hive",
        "path",
        "value_name",
        "reg_type",
        "expected",
        "pattern",
    }
)

SEVERITIES = frozenset({"low", "medium", "high"})
ID_RE = re.compile(r"^V-\d+$")


@dataclass(frozen=True)
class Check:
    """One STIG check, with no stored result."""

    id: str
    title: str
    severity: str
    test_type: str
    description: str
    fix_text: str
    reference: dict[str, Any] | None
    rule_id: str | None
    hive: str | None
    path: str | None
    value_name: str | None
    reg_type: str | None
    expected: Any
    pattern: str | None

    @property
    def kind(self) -> str:
        """``manual``, ``pattern``, or ``value``."""
        if self.test_type == "manual":
            return "manual"
        if self.pattern is not None:
            return "pattern"
        return "value"

    @property
    def is_automated(self) -> bool:
        return self.test_type == "automated"

    def validate(self) -> None:
        """Fail loudly on a malformed check instead of silently skipping it."""
        if not ID_RE.match(self.id):
            raise ValueError(f"check id must look like V-######, got {self.id!r}")
        if not self.title:
            raise ValueError(f"check {self.id}: title is empty")
        if self.severity not in SEVERITIES:
            raise ValueError(f"check {self.id}: unknown severity {self.severity!r}")
        if self.test_type not in ("automated", "manual"):
            raise ValueError(f"check {self.id}: unknown test_type {self.test_type!r}")
        # A stray reg_type or pattern on a manual check is validated
        # too: manual means "no registry target", not "anything goes".
        if self.reg_type is not None and self.reg_type not in REG_TYPE_NAMES:
            raise ValueError(f"check {self.id}: unknown reg_type {self.reg_type!r}")
        if self.pattern is not None:
            if self.expected is not None:
                raise ValueError(
                    f"check {self.id}: pattern checks must not also set expected"
                )
            try:
                re.compile(self.pattern)
            except re.error as exc:
                raise ValueError(
                    f"check {self.id}: invalid pattern {self.pattern!r}: {exc}"
                ) from exc
        if self.test_type == "manual":
            return
        if not self.hive or not self.path or not self.value_name or not self.reg_type:
            raise ValueError(
                f"check {self.id}: automated check needs hive, path, "
                "value_name and reg_type"
            )
        if self.pattern is None and self.expected is None:
            raise ValueError(
                f"check {self.id}: automated check needs expected or pattern"
            )
        if self.pattern is None:
            # Validates the shape of the expected value(s) for the type.
            values = (
                self.expected if isinstance(self.expected, list) else [self.expected]
            )
            if isinstance(self.expected, list) and not values:
                raise ValueError(f"check {self.id}: empty expected list")
            for value in values:
                coerce_value(self.reg_type, value)


def check_from_dict(data: dict[str, Any], *, source: str) -> Check:
    """Build and validate a :class:`Check` from one JSON object."""
    unknown = set(data) - CHECK_FIELDS
    if unknown:
        raise ValueError(f"{source}: unknown check field(s): {sorted(unknown)}")
    missing = CHECK_FIELDS - set(data)
    if missing:
        raise ValueError(f"{source}: missing check field(s): {sorted(missing)}")
    check = Check(
        id=data["id"],
        title=data["title"],
        severity=data["severity"],
        test_type=data["test_type"],
        description=data["description"],
        fix_text=data["fix_text"],
        reference=data["reference"],
        rule_id=data["rule_id"],
        hive=data["hive"],
        path=data["path"],
        value_name=data["value_name"],
        reg_type=data["reg_type"],
        expected=data["expected"],
        pattern=data["pattern"],
    )
    check.validate()
    return check


def default_data_dir() -> Path:
    return Path(__file__).resolve().parent / "data"


def resolve_app(name: str) -> str:
    """Resolve a CLI/GUI app name or alias to its canonical key."""
    key = APP_ALIASES.get(name.strip().lower())
    if key is None:
        raise ValueError(
            f"unknown app {name!r}; expected one of: {', '.join(sorted(APPS))}"
        )
    return key


def load_checks(app: str, data_dir: Path | None = None) -> list[Check]:
    """Load and validate one app's checks from its bundled JSON file."""
    key = resolve_app(app)
    directory = Path(data_dir) if data_dir is not None else default_data_dir()
    path = directory / f"{key}.json"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"check data not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid check data in {path}: {exc}") from exc
    if not isinstance(raw, dict) or raw.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            f"{path}: expected schema_version {SCHEMA_VERSION}, "
            f"got {raw.get('schema_version') if isinstance(raw, dict) else type(raw)}"
        )
    if raw.get("app") != APPS[key]:
        raise ValueError(f"{path}: app name mismatch: {raw.get('app')!r}")
    entries = raw.get("checks")
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"{path}: 'checks' must be a non-empty list")
    checks = [check_from_dict(entry, source=str(path)) for entry in entries]
    ids = [check.id for check in checks]
    if len(set(ids)) != len(ids):
        raise ValueError(f"{path}: duplicate check id(s)")
    return checks


def load_all_checks(data_dir: Path | None = None) -> dict[str, list[Check]]:
    """Load every bundled app's checks, keyed by canonical app key."""
    return {key: load_checks(key, data_dir) for key in APPS}
