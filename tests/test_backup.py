"""Tests for per-value backup/restore round trips."""

import pytest

from stig_registry_toolkit.backup import (
    BackupError,
    BackupStore,
    PriorState,
    capture_prior,
    restore_latest,
    restore_record,
)
from stig_registry_toolkit.checks import load_checks
from stig_registry_toolkit.registry import FakeRegistryBackend

PATH = r"SOFTWARE\Policies\Google\Chrome"


def test_record_restore_existing_value(tmp_path):
    backend = FakeRegistryBackend()
    store = BackupStore(tmp_path)
    check = load_checks("chrome")[0]
    backend.seed(check.hive, check.path, check.value_name, "REG_DWORD", 1)
    prior = capture_prior(backend, check)
    assert prior.existed is True
    store.record("chrome", check, prior)
    backend.write(check.hive, check.path, check.value_name, "REG_DWORD", 99)
    detail = restore_latest(store, backend, "chrome", check.id)
    assert "restored" in detail
    assert backend.read(check.hive, check.path, check.value_name)[0] == 1


def test_restore_absent_prior_removes_value(tmp_path):
    backend = FakeRegistryBackend()
    store = BackupStore(tmp_path)
    check = load_checks("chrome")[0]
    prior = capture_prior(backend, check)
    assert prior.existed is False
    store.record("chrome", check, prior)
    backend.write("HKEY_LOCAL_MACHINE", PATH, check.value_name, "REG_DWORD", 0)
    restore_latest(store, backend, "chrome", check.id)
    with pytest.raises(Exception, match="does not exist"):
        backend.read("HKEY_LOCAL_MACHINE", PATH, check.value_name)


def test_restore_without_backup_raises(tmp_path):
    backend = FakeRegistryBackend()
    store = BackupStore(tmp_path)
    with pytest.raises(BackupError, match="no backup recorded"):
        restore_latest(store, backend, "chrome", "V-221558")


def test_latest_wins_and_latest_for_app(tmp_path):
    store = BackupStore(tmp_path)
    checks = load_checks("chrome")[:2]
    store.record(
        "chrome", checks[0], PriorState(existed=True, value=1, reg_type="REG_DWORD")
    )
    store.record(
        "chrome", checks[0], PriorState(existed=True, value=2, reg_type="REG_DWORD")
    )
    store.record("chrome", checks[1], PriorState(existed=False))
    assert store.latest("chrome", checks[0].id).prior.value == 2
    latest = store.latest_for_app("chrome")
    assert len(latest) == 2
    assert latest[0].prior.value == 2


def test_bytes_values_round_trip(tmp_path):
    backend = FakeRegistryBackend()
    store = BackupStore(tmp_path)
    check = load_checks("chrome")[0]
    store.record(
        "chrome",
        check,
        PriorState(existed=True, value=b"\x00\xff", reg_type="REG_BINARY"),
    )
    record = store.latest("chrome", check.id)
    assert record.prior.value == b"\x00\xff"
    detail = restore_record(backend, record)
    assert "restored" in detail
    assert backend.read("HKEY_LOCAL_MACHINE", PATH, check.value_name) == (
        b"\x00\xff",
        "REG_BINARY",
    )


def test_corrupt_store_raises(tmp_path):
    store = BackupStore(tmp_path)
    store.path.write_text("{bad json", encoding="utf-8")
    with pytest.raises(BackupError, match="corrupt"):
        store.load_records()


def test_store_does_not_create_directory_on_open(tmp_path):
    directory = tmp_path / "not-created"
    store = BackupStore(directory)
    assert not directory.exists()
    assert store.load_records() == []
    check = load_checks("chrome")[0]
    store.record("chrome", check, PriorState(existed=False))
    assert directory.exists()
    assert (directory / "backups.json").exists()


def test_store_format_is_versioned_and_reads_legacy(tmp_path):
    import json

    store = BackupStore(tmp_path)
    check = load_checks("chrome")[0]
    store.record(
        "chrome", check, PriorState(existed=True, value=1, reg_type="REG_DWORD")
    )
    raw = json.loads(store.path.read_text(encoding="utf-8"))
    assert raw["version"] == 1
    assert len(raw["records"]) == 1
    # Files written by 2.1.0 and earlier are a bare records list.
    store.path.write_text(json.dumps(raw["records"]), encoding="utf-8")
    assert len(store.load_records()) == 1
    # Unknown versions and wrong shapes fail as corrupt, not KeyError.
    store.path.write_text(json.dumps({"version": 99, "records": []}), encoding="utf-8")
    with pytest.raises(BackupError, match="corrupt"):
        store.load_records()
    store.path.write_text(json.dumps({"version": 1}), encoding="utf-8")
    with pytest.raises(BackupError, match="corrupt"):
        store.load_records()
