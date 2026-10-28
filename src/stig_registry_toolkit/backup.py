"""Per-value backups and hive backups, plus restore.

Every fix records the value it is about to change (or the fact that the
value did not exist) in a JSON backup file first, so a fix can be
undone without restoring a whole hive. Hive backups via ``reg save``
are a separate, coarser safety net and live in the same directory.
"""

from __future__ import annotations

import datetime
import json
import os
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .checks import Check
from .registry import (
    RegistryBackend,
    RegistryNotFoundError,
    coerce_value,
    normalize_hive,
    normalize_path,
)


class BackupError(Exception):
    """A backup or restore operation failed."""


@dataclass(frozen=True)
class PriorState:
    """What a value looked like before a fix touched it."""

    existed: bool
    value: Any = None
    reg_type: str | None = None


@dataclass(frozen=True)
class BackupRecord:
    """One recorded prior state, identified by app + check id."""

    timestamp: str
    app: str
    check_id: str
    hive: str
    path: str
    value_name: str
    prior: PriorState


def _encode_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"__bytes_hex__": value.hex()}
    if isinstance(value, (list, tuple)):
        return [_encode_value(item) for item in value]
    return value


def _decode_value(value: Any) -> Any:
    if isinstance(value, dict) and set(value) == {"__bytes_hex__"}:
        return bytes.fromhex(value["__bytes_hex__"])
    if isinstance(value, list):
        return [_decode_value(item) for item in value]
    return value


def _record_to_dict(record: BackupRecord) -> dict[str, Any]:
    data = asdict(record)
    data["prior"]["value"] = _encode_value(record.prior.value)
    return data


def _record_from_dict(data: dict[str, Any]) -> BackupRecord:
    prior = data["prior"]
    return BackupRecord(
        timestamp=data["timestamp"],
        app=data["app"],
        check_id=data["check_id"],
        hive=data["hive"],
        path=data["path"],
        value_name=data["value_name"],
        prior=PriorState(
            existed=bool(prior["existed"]),
            value=_decode_value(prior.get("value")),
            reg_type=prior.get("reg_type"),
        ),
    )


class BackupStore:
    """Append-only JSON store of per-value prior states."""

    FILENAME = "backups.json"

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / self.FILENAME

    def record(self, app: str, check: Check, prior: PriorState) -> BackupRecord:
        """Append one record. Callers must pass the pre-fix state."""
        assert check.hive is not None and check.path is not None
        assert check.value_name is not None
        record = BackupRecord(
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            app=app,
            check_id=check.id,
            hive=normalize_hive(check.hive),
            path=normalize_path(check.path),
            value_name=check.value_name,
            prior=prior,
        )
        records = self.load_records()
        records.append(record)
        self.path.write_text(
            json.dumps([_record_to_dict(r) for r in records], indent=2),
            encoding="utf-8",
        )
        return record

    def load_records(self) -> list[BackupRecord]:
        if not self.path.exists():
            return []
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise BackupError(f"backup store is corrupt: {self.path}: {exc}") from exc
        if not isinstance(raw, list):
            raise BackupError(f"backup store is corrupt: {self.path}")
        return [_record_from_dict(item) for item in raw]

    def latest(self, app: str, check_id: str) -> BackupRecord | None:
        """The most recent record for one check, or None."""
        matches = [
            r for r in self.load_records() if r.app == app and r.check_id == check_id
        ]
        return matches[-1] if matches else None

    def latest_for_app(self, app: str) -> list[BackupRecord]:
        """The most recent record per check id for one app."""
        latest: dict[str, BackupRecord] = {}
        for record in self.load_records():
            if record.app == app:
                latest[record.check_id] = record
        return [latest[key] for key in sorted(latest)]


def capture_prior(backend: RegistryBackend, check: Check) -> PriorState:
    """Read the current state of a check's value, tolerating absence."""
    assert check.hive is not None and check.path is not None
    assert check.value_name is not None
    try:
        value, reg_type = backend.read(check.hive, check.path, check.value_name)
    except RegistryNotFoundError:
        return PriorState(existed=False)
    return PriorState(existed=True, value=value, reg_type=reg_type)


def restore_record(
    backend: RegistryBackend, record: BackupRecord, *, create_keys: bool = True
) -> str:
    """Restore one prior state. Returns a short description of what happened."""
    if not record.prior.existed:
        try:
            backend.delete_value(record.hive, record.path, record.value_name)
        except RegistryNotFoundError:
            return "already absent"
        return "value removed (did not exist before the fix)"
    assert record.prior.reg_type is not None
    data = coerce_value(record.prior.reg_type, record.prior.value)
    backend.write(
        record.hive,
        record.path,
        record.value_name,
        record.prior.reg_type,
        data,
        create_keys=create_keys,
    )
    return f"restored {record.prior.value!r} ({record.prior.reg_type})"


def restore_latest(
    store: BackupStore,
    backend: RegistryBackend,
    app: str,
    check_id: str,
) -> str:
    """Restore the latest backup for one check."""
    record = store.latest(app, check_id)
    if record is None:
        raise BackupError(f"no backup recorded for {app} check {check_id}")
    return restore_record(backend, record)


# --- Hive backups (Windows ``reg save``) ---

HIVES_TO_BACKUP: dict[str, str] = {
    "SYSTEM": r"HKEY_LOCAL_MACHINE\SYSTEM",
    "SOFTWARE": r"HKEY_LOCAL_MACHINE\SOFTWARE",
    "CURRENT_USER": r"HKEY_CURRENT_USER",
}


def backup_hive(hive_path: str, directory: str | Path) -> Path:
    """Save one hive with ``reg save``. Raises BackupError on failure."""
    dest_dir = Path(directory)
    dest_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    leaf = hive_path.rsplit("\\", 1)[-1].replace(" ", "_")
    dest = dest_dir / f"registry_backup_{leaf}_{stamp}.hiv"
    startupinfo: Any = None
    if os.name == "nt":
        # STARTUPINFO exists only on Windows; getattr keeps this
        # importable (and type-checkable) on other platforms.
        startupinfo_cls = getattr(subprocess, "STARTUPINFO", None)
        if startupinfo_cls is not None:
            startupinfo = startupinfo_cls()
            startupinfo.dwFlags |= getattr(subprocess, "STARTF_USESHOWWINDOW", 0)
            startupinfo.wShowWindow = getattr(subprocess, "SW_HIDE", 0)
    try:
        completed = subprocess.run(
            ["reg", "save", hive_path, str(dest), "/y"],
            check=True,
            capture_output=True,
            text=True,
            timeout=300,
            startupinfo=startupinfo,
        )
    except FileNotFoundError as exc:
        raise BackupError("'reg' was not found; hive backup needs Windows") from exc
    except subprocess.TimeoutExpired as exc:
        raise BackupError(f"timed out backing up {hive_path}") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or "").strip() or "no error details from reg save"
        raise BackupError(f"failed to back up {hive_path}: {detail}") from exc
    if not dest.exists() or dest.stat().st_size == 0:
        raise BackupError(f"reg save reported success but {dest} is empty")
    _ = completed
    return dest


def backup_all_hives(
    directory: str | Path, hives: dict[str, str] | None = None
) -> list[Path]:
    """Back up the standard hives. Stops at the first failure."""
    return [
        backup_hive(path, directory) for path in (hives or HIVES_TO_BACKUP).values()
    ]
