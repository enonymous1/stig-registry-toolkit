"""CLI tests against the fake registry (no real writes anywhere)."""

import json
from pathlib import Path

from stig_registry_toolkit.checks import load_checks
from stig_registry_toolkit.cli import format_results, main
from stig_registry_toolkit.engine import verify_all
from stig_registry_toolkit.registry import FakeRegistryBackend

PATH = r"SOFTWARE\Policies\Google\Chrome"


def _seed_passing(backend: FakeRegistryBackend) -> None:
    for check in load_checks("chrome"):
        if check.is_automated and check.pattern is None:
            expected = check.expected
            value = expected[0] if isinstance(expected, list) else expected
            backend.seed(
                check.hive, check.path, check.value_name, check.reg_type, value
            )
    for check in load_checks("adobe"):
        if check.is_automated:
            backend.seed(
                check.hive, check.path, check.value_name, check.reg_type, check.expected
            )


def test_check_exit_codes(capsys):
    backend = FakeRegistryBackend()
    assert main(["check", "--app", "chrome"], backend=backend) == 1
    _seed_passing(backend)
    # The pattern check still fails (no URL seeded), so chrome stays 1.
    assert main(["check", "--app", "chrome"], backend=backend) == 1
    out = capsys.readouterr().out
    assert "V-221565" in out


def test_check_json_format(capsys):
    backend = FakeRegistryBackend()
    _seed_passing(backend)
    code = main(["check", "--app", "adobe", "--format", "json"], backend=backend)
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload) == 26
    assert all(
        item["status"] == "pass" for item in payload if item["test_type"] == "automated"
    )
    assert any(item["status"] == "manual" for item in payload)


def test_fix_requires_yes_and_dry_run_changes_nothing(tmp_path: Path):
    backend = FakeRegistryBackend()
    assert (
        main(["fix", "--app", "chrome", "--backup-dir", str(tmp_path)], backend=backend)
        == 2
    )
    assert backend.snapshot() == {}
    assert (
        main(
            ["fix", "--app", "chrome", "--dry-run", "--backup-dir", str(tmp_path)],
            backend=backend,
        )
        == 1
    )
    assert backend.snapshot() == {}
    assert not (tmp_path / "backups.json").exists()


def test_fix_with_yes_then_restore(tmp_path: Path):
    backend = FakeRegistryBackend()
    assert (
        main(
            ["fix", "--app", "chrome", "--yes", "--backup-dir", str(tmp_path)],
            backend=backend,
        )
        == 1
    )
    # Pattern check cannot be fixed, so one failure remains; everything
    # else was written.
    assert backend.snapshot()
    assert (
        main(
            ["restore", "--app", "chrome", "--yes", "--backup-dir", str(tmp_path)],
            backend=backend,
        )
        == 0
    )
    assert backend.snapshot() == {}


def test_fix_single_check_id(tmp_path: Path):
    backend = FakeRegistryBackend()
    code = main(
        [
            "fix",
            "--app",
            "chrome",
            "--check-id",
            "V-221558",
            "--yes",
            "--backup-dir",
            str(tmp_path),
        ],
        backend=backend,
    )
    assert code == 0
    assert len(backend.snapshot()) == 1
    code = main(
        [
            "fix",
            "--app",
            "chrome",
            "--check-id",
            "V-999999",
            "--yes",
            "--backup-dir",
            str(tmp_path),
        ],
        backend=backend,
    )
    assert code == 2


def test_restore_requires_yes(tmp_path: Path):
    backend = FakeRegistryBackend()
    assert (
        main(
            ["restore", "--app", "chrome", "--backup-dir", str(tmp_path)],
            backend=backend,
        )
        == 2
    )


def test_list_does_not_touch_registry(capsys):
    backend = FakeRegistryBackend()
    assert main(["list", "--app", "adobe"], backend=backend) == 0
    assert backend.snapshot() == {}
    assert "V-213168" in capsys.readouterr().out


def test_report_writes_file(tmp_path: Path):
    backend = FakeRegistryBackend()
    out = tmp_path / "report.json"
    code = main(
        ["report", "--app", "adobe", "--format", "json", "--output", str(out)],
        backend=backend,
    )
    assert code == 1  # unseeded registry: failures present
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert len(payload) == 26


def test_unknown_app_is_usage_error():
    backend = FakeRegistryBackend()
    assert main(["check", "--app", "firefox"], backend=backend) == 2


def test_format_results_csv_and_text():
    backend = FakeRegistryBackend()
    results = verify_all(load_checks("adobe")[:2], backend)
    text = format_results("adobe", results, "text")
    assert "Summary:" in text
    csv_text = format_results("adobe", results, "csv")
    assert csv_text.splitlines()[0].startswith("app,id,title")
    assert len(csv_text.splitlines()) == 3
