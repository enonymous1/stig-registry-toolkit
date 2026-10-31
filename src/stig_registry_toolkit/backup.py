"""Per-value backups and hive backups, plus restore.

Every fix records the value it is about to change (or the fact that the
value did not exist) in a JSON backup file first, so a fix can be
undone without restoring a whole hive. Hive backups via ``reg save``
are a separate, coarser safety net and live in the same directory.
"""

from __future__ import annotations

import contextlib
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


# Default directory for per-value backups (and hive dumps). The CLI
# and GUI share this one constant instead of each spelling it out.
DEFAULT_BACKUP_DIR = Path("stig-registry-toolkit-backups")

# Format version of backups.json. Version 1 is the {"version", "records"}
# object; files written by 2.1.0 and earlier are a bare records list
# and still load (see ``load_records``). Bump this only with a loader
# that still reads every older version.
STORE_VERSION = 1


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


def _records_to_dict(records: list[BackupRecord]) -> dict[str, Any]:
    return {
        "version": STORE_VERSION,
        "records": [_record_to_dict(r) for r in records],
    }


class BackupStore:
    """Append-only JSON store of per-value prior states.

    The store file is versioned (see ``STORE_VERSION``) and written
    atomically: a crash mid-write leaves either the old file or the
    new one, never a half-written backups.json.
    """

    FILENAME = "backups.json"

    def __init__(self, directory: str | Path) -> None:
        # Deliberately no mkdir here: merely opening the store to
        # read (for example, a restore preview) must not create a
        # backup directory as a side effect. The directory is
        # created by record(), the only operation that writes.
        self.directory = Path(directory)
        self.path = self.directory / self.FILENAME

    def record(self, app: str, check: Check, prior: PriorState) -> BackupRecord:
        """Append one record. Callers must pass the pre-fix state."""
        assert check.hive is not None and check.path is not None
        assert check.value_name is not None
        self.directory.mkdir(parents=True, exist_ok=True)
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
        tmp = self.path.with_name(self.path.name + ".tmp")
        try:
            tmp.write_text(
                json.dumps(_records_to_dict(records), indent=2),
                encoding="utf-8",
            )
            os.replace(tmp, self.path)
        finally:
            with contextlib.suppress(OSError):
                tmp.unlink(missing_ok=True)
        return record

    def load_records(self) -> list[BackupRecord]:
        if not self.path.exists():
            return []
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise BackupError(f"backup store is corrupt: {self.path}: {exc}") from exc
        if isinstance(raw, list):
            # Written by 2.1.0 and earlier (bare records list).
            data = raw
        elif (
            isinstance(raw, dict)
            and raw.get("version") == STORE_VERSION
            and isinstance(raw.get("records"), list)
        ):
            data = raw["records"]
        else:
            raise BackupError(
                f"backup store is corrupt: {self.path} (unknown format or version)"
            )
        try:
            return [_record_from_dict(item) for item in data]
        except (KeyError, TypeError, AttributeError, ValueError) as exc:
            raise BackupError(f"backup store is corrupt: {self.path}: {exc}") from exc

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
    # Two backups of one hive within the same second must not silently
    # overwrite each other (reg save is called with /y).
    suffix = 2
    while dest.exists():
        dest = dest_dir / f"registry_backup_{leaf}_{stamp}_{suffix}.hiv"
        suffix += 1
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
        subprocess.run(
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
    return dest


def backup_all_hives(
    directory: str | Path, hives: dict[str, str] | None = None
) -> list[Path]:
    """Back up the standard hives. Stops at the first failure."""
    return [
        backup_hive(path, directory) for path in (hives or HIVES_TO_BACKUP).values()
    ]
