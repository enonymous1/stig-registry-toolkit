"""Tests for verification and fixing against the fake registry."""

from stig_registry_toolkit.backup import BackupStore
from stig_registry_toolkit.checks import Check, load_checks
from stig_registry_toolkit.engine import fix_all, fix_check, verify_all, verify_check
from stig_registry_toolkit.registry import FakeRegistryBackend, RegistryError

CHROME_PATH = r"SOFTWARE\Policies\Google\Chrome"
ADOBE_PATH = r"Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown"


def _check(**overrides):
    data = {
        "id": "V-1",
        "title": "Example",
        "severity": "medium",
        "test_type": "automated",
        "description": "d",
        "fix_text": "f",
        "reference": None,
        "rule_id": None,
        "hive": "HKEY_LOCAL_MACHINE",
        "path": CHROME_PATH,
        "value_name": "ExampleValue",
        "reg_type": "REG_DWORD",
        "expected": 0,
        "pattern": None,
    }
    data.update(overrides)
    return Check(**data)


def test_verify_pass_fail_missing_type_mismatch():
    backend = FakeRegistryBackend()
    check = _check()
    assert verify_check(check, backend).status == "fail"  # missing
    backend.seed("HKEY_LOCAL_MACHINE", CHROME_PATH, "ExampleValue", "REG_DWORD", 1)
    assert verify_check(check, backend).status == "fail"  # wrong value
    backend.seed("HKEY_LOCAL_MACHINE", CHROME_PATH, "ExampleValue", "REG_DWORD", 0)
    assert verify_check(check, backend).status == "pass"
    backend.seed("HKEY_LOCAL_MACHINE", CHROME_PATH, "ExampleValue", "REG_SZ", "0")
    result = verify_check(check, backend)
    assert result.status == "fail"
    assert "type mismatch" in result.detail


def test_verify_anyof_and_pattern():
    backend = FakeRegistryBackend()
    anyof = _check(expected=[1, 2])
    backend.seed("HKEY_LOCAL_MACHINE", CHROME_PATH, "ExampleValue", "REG_DWORD", 3)
    assert verify_check(anyof, backend).status == "fail"
    backend.seed("HKEY_LOCAL_MACHINE", CHROME_PATH, "ExampleValue", "REG_DWORD", 2)
    assert verify_check(anyof, backend).status == "pass"
    pattern = _check(
        expected=None,
        pattern="^https",
        reg_type="REG_SZ",
        value_name="SearchURL",
    )
    backend.seed(
        "HKEY_LOCAL_MACHINE", CHROME_PATH, "SearchURL", "REG_SZ", "http://example.test"
    )
    assert verify_check(pattern, backend).status == "fail"
    backend.seed(
        "HKEY_LOCAL_MACHINE",
        CHROME_PATH,
        "SearchURL",
        "REG_SZ",
        "https://example.test/?q={searchTerms}",
    )
    assert verify_check(pattern, backend).status == "pass"


def test_verify_manual_never_touches_registry():
    backend = FakeRegistryBackend()
    check = _check(
        test_type="manual",
        hive=None,
        path=None,
        value_name=None,
        reg_type=None,
        expected=None,
    )
    result = verify_check(check, backend)
    assert result.status == "manual"


def test_verify_error_status_on_backend_failure():
    class Broken(FakeRegistryBackend):
        def read(self, hive, path, value_name):  # type: ignore[override]
            raise RegistryError("boom")

    result = verify_check(_check(), Broken())
    assert result.status == "error"
    assert "boom" in result.detail


def test_fix_writes_reverifies_and_backs_up(tmp_path):
    backend = FakeRegistryBackend()
    backend.seed("HKEY_LOCAL_MACHINE", CHROME_PATH, "ExampleValue", "REG_DWORD", 1)
    store = BackupStore(tmp_path)
    outcome = fix_check(_check(), backend, app="chrome", backup_store=store)
    assert outcome.changed is True
    assert outcome.backup_recorded is True
    assert backend.read("HKEY_LOCAL_MACHINE", CHROME_PATH, "ExampleValue") == (
        0,
        "REG_DWORD",
    )
    record = store.latest("chrome", "V-1")
    assert record is not None
    assert record.prior.existed is True
    assert record.prior.value == 1


def test_fix_noop_when_passing_and_records_no_backup(tmp_path):
    backend = FakeRegistryBackend()
    backend.seed("HKEY_LOCAL_MACHINE", CHROME_PATH, "ExampleValue", "REG_DWORD", 0)
    store = BackupStore(tmp_path)
    outcome = fix_check(_check(), backend, app="chrome", backup_store=store)
    assert outcome.changed is False
    assert store.load_records() == []


def test_fix_pattern_and_manual_are_not_auto_fixed(tmp_path):
    backend = FakeRegistryBackend()
    store = BackupStore(tmp_path)
    pattern = _check(
        expected=None, pattern="^https", reg_type="REG_SZ", value_name="SearchURL"
    )
    outcome = fix_check(pattern, backend, app="chrome", backup_store=store)
    assert outcome.changed is False
    manual = _check(
        test_type="manual",
        hive=None,
        path=None,
        value_name=None,
        reg_type=None,
        expected=None,
    )
    outcome = fix_check(manual, backend, app="chrome", backup_store=store)
    assert outcome.changed is False
    assert store.load_records() == []


def test_fix_missing_value_records_absent_prior(tmp_path):
    backend = FakeRegistryBackend()
    store = BackupStore(tmp_path)
    outcome = fix_check(_check(), backend, app="chrome", backup_store=store)
    assert outcome.changed is True
    record = store.latest("chrome", "V-1")
    assert record is not None and record.prior.existed is False


def test_fix_all_continues_past_failure():
    class Flaky(FakeRegistryBackend):
        def write(self, hive, path, value_name, reg_type, value, **kwargs):  # type: ignore[override]
            if value_name == "BadValue":
                raise RegistryError("denied")
            super().write(hive, path, value_name, reg_type, value, **kwargs)

    backend = Flaky()
    checks = [_check(id="V-1"), _check(id="V-2", value_name="BadValue")]
    outcomes = fix_all(checks, backend, app="chrome")
    assert outcomes[0].changed is True
    assert outcomes[1].changed is False
    assert "denied" in outcomes[1].detail


def test_real_bundled_checks_verify_against_seeded_registry():
    """Seed one Chrome + one Adobe value and confirm the engine reads them."""
    backend = FakeRegistryBackend()
    chrome = {c.id: c for c in load_checks("chrome")}
    check = chrome["V-221558"]
    assert check.value_name == "RemoteAccessHostFirewallTraversal"
    backend.seed(check.hive, check.path, check.value_name, "REG_DWORD", 0)
    assert verify_check(check, backend).status == "pass"
    adobe = {c.id: c for c in load_checks("adobe")}
    acheck = adobe["V-213168"]
    backend.seed(acheck.hive, acheck.path, acheck.value_name, "REG_DWORD", 1)
    assert verify_check(acheck, backend).status == "pass"
    results = verify_all(load_checks("adobe"), backend)
    assert sum(1 for r in results if r.status == "pass") == 1


def test_fix_anyof_writes_first_allowed_value(tmp_path):
    backend = FakeRegistryBackend()
    store = BackupStore(tmp_path)
    outcome = fix_check(
        _check(expected=[1, 2]), backend, app="chrome", backup_store=store
    )
    assert outcome.changed is True
    assert backend.read("HKEY_LOCAL_MACHINE", CHROME_PATH, "ExampleValue")[0] == 1
