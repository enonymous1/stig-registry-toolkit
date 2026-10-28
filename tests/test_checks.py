"""Tests for check loading and schema validation (no registry needed)."""

from pathlib import Path

import pytest

from stig_registry_toolkit.checks import (
    APPS,
    Check,
    check_from_dict,
    load_all_checks,
    load_checks,
    resolve_app,
)


def _base_check(**overrides):
    data = {
        "id": "V-100001",
        "title": "Example check",
        "severity": "medium",
        "test_type": "automated",
        "description": "d",
        "fix_text": "f",
        "reference": None,
        "rule_id": None,
        "hive": "HKEY_LOCAL_MACHINE",
        "path": r"SOFTWARE\Policies\Example",
        "value_name": "ExampleValue",
        "reg_type": "REG_DWORD",
        "expected": 1,
        "pattern": None,
    }
    data.update(overrides)
    return data


def test_load_counts_and_uniqueness():
    all_checks = load_all_checks()
    assert set(all_checks) == set(APPS)
    assert len(all_checks["chrome"]) == 42
    assert len(all_checks["adobe"]) == 26
    for checks in all_checks.values():
        ids = [c.id for c in checks]
        assert len(set(ids)) == len(ids)
        assert all(c.id.startswith("V-") for c in checks)


def test_every_automated_check_has_a_target():
    for checks in load_all_checks().values():
        for check in checks:
            if check.is_automated:
                assert check.hive and check.path and check.value_name
                assert check.reg_type in ("REG_DWORD", "REG_SZ")
                assert check.expected is not None or check.pattern is not None


def test_pattern_and_anyof_checks_are_represented():
    chrome = {c.id: c for c in load_checks("chrome")}
    pattern = chrome["V-221565"]
    assert pattern.kind == "pattern"
    assert pattern.pattern == "^https"
    assert pattern.expected is None
    assert pattern.reg_type == "REG_SZ"
    for check_id in ("V-221580", "V-221588"):
        assert chrome[check_id].expected == [1, 2]
    manual_ids = [c.id for c in chrome.values() if c.test_type == "manual"]
    assert manual_ids == ["V-221584", "V-221596"]
    adobe = {c.id: c for c in load_checks("adobe")}
    assert adobe["V-213192"].kind == "manual"
    assert adobe["V-213192"].rule_id is not None
    assert adobe["V-213168"].reference["publisher"] == "DISA"


def test_safe_browsing_spelling_uses_json_form():
    chrome = {c.id: c for c in load_checks("chrome")}
    assert chrome["V-221580"].value_name == "SafeBrowsingProtectionLevel"
    assert chrome["V-221590"].value_name == "SafeBrowsingExtendedReportingEnabled"


def test_resolve_app_aliases():
    assert resolve_app("google-chrome") == "chrome"
    assert resolve_app("Adobe-DC") == "adobe"
    with pytest.raises(ValueError):
        resolve_app("firefox")


def test_unknown_field_rejected():
    data = _base_check(extra_field=1)
    with pytest.raises(ValueError, match="unknown check field"):
        check_from_dict(data, source="test")


def test_missing_field_rejected():
    data = _base_check()
    del data["expected"]
    with pytest.raises(ValueError, match="missing check field"):
        check_from_dict(data, source="test")


def test_bad_severity_bad_id_bad_regex_rejected():
    with pytest.raises(ValueError):
        check_from_dict(_base_check(severity="urgent"), source="test")
    with pytest.raises(ValueError):
        check_from_dict(_base_check(id="STIG-1"), source="test")
    with pytest.raises(ValueError):
        check_from_dict(_base_check(expected=None, pattern="[unclosed"), source="test")


def test_manual_check_needs_no_target():
    check = check_from_dict(
        _base_check(
            test_type="manual",
            hive=None,
            path=None,
            value_name=None,
            reg_type=None,
            expected=None,
        ),
        source="test",
    )
    assert check.kind == "manual"


def test_automated_check_without_target_rejected():
    with pytest.raises(ValueError, match="needs hive"):
        check_from_dict(_base_check(path=None), source="test")


def test_malformed_data_dir(tmp_path: Path):
    bad = tmp_path / "chrome.json"
    bad.write_text(
        '{"schema_version": 99, "app": "Google Chrome", "checks": []}', encoding="utf-8"
    )
    with pytest.raises(ValueError, match="schema_version"):
        load_checks("chrome", tmp_path)
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid check data"):
        load_checks("chrome", tmp_path)
    missing = tmp_path / "empty"
    missing.mkdir()
    with pytest.raises(ValueError, match="not found"):
        load_checks("chrome", missing)


def test_check_is_frozen():
    check = Check(**_base_check())
    with pytest.raises(AttributeError):
        check.title = "changed"  # type: ignore[misc]
