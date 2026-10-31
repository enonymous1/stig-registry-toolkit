"""Command-line interface: check, fix, backup, restore, report, gui, split.

Safety rules, enforced here and in the GUI:

* ``fix`` and ``restore`` refuse to change anything without ``--yes``,
  unless they are dry runs.
* A dry run verifies only; it writes nothing and records no backup.
* Every real fix records the prior value first (see ``backup.py``).
* Results are never written back into the bundled check data.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .backup import (
    DEFAULT_BACKUP_DIR,
    BackupError,
    BackupStore,
    backup_all_hives,
    restore_record,
)
from .checks import APPS, load_checks, resolve_app
from .engine import CheckResult, can_auto_fix, fix_all, verify_all
from .registry import (
    RegistryBackend,
    RegistryUnavailableError,
    create_backend,
    is_admin,
)
from .split import SplitError, split_stig_csv


def _report_value(value: Any) -> Any:
    """Make a registry value safe for JSON and CSV reports.

    Bytes (REG_BINARY) are not JSON-serializable, so they become a
    hex string; lists are converted element-wise for the same reason.
    Everything else passes through unchanged.
    """
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (list, tuple)):
        return [_report_value(item) for item in value]
    return value


def _require_backend(backend: RegistryBackend | None, view: str) -> RegistryBackend:
    if backend is not None:
        return backend
    return create_backend(view=view)


def format_results(app: str, results: list[CheckResult], fmt: str) -> str:
    """Render verification results as text, JSON, or CSV."""
    if fmt == "json":
        payload = [
            {
                "app": app,
                "id": r.check.id,
                "title": r.check.title,
                "severity": r.check.severity,
                "test_type": r.check.test_type,
                "status": r.status,
                "detail": r.detail,
                "actual": _report_value(r.actual),
                "actual_type": r.actual_type,
            }
            for r in results
        ]
        return json.dumps(payload, indent=2)
    if fmt == "csv":
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(
            [
                "app",
                "id",
                "title",
                "severity",
                "test_type",
                "status",
                "detail",
                "actual",
                "actual_type",
            ]
        )
        for r in results:
            writer.writerow(
                [
                    app,
                    r.check.id,
                    r.check.title,
                    r.check.severity,
                    r.check.test_type,
                    r.status,
                    r.detail,
                    _report_value(r.actual),
                    r.actual_type,
                ]
            )
        return buffer.getvalue()
    lines = [f"{APPS[app]}: {len(results)} checks"]
    for r in results:
        lines.append(f"  {r.status.upper():6} {r.check.id}  {r.check.title}")
        if r.status in ("fail", "error"):
            lines.append(f"         {r.detail}")
    counts = {s: 0 for s in ("pass", "fail", "manual", "error")}
    for r in results:
        counts[r.status] += 1
    lines.append(
        "  Summary: "
        + ", ".join(f"{counts[s]} {s}" for s in ("pass", "fail", "manual", "error"))
    )
    return "\n".join(lines)


def _iter_apps(app_arg: str) -> list[str]:
    """Canonical app keys for an --app value; "all" means every app."""
    if app_arg == "all":
        return list(APPS)
    return [resolve_app(app_arg)]


def _require_confirmation(args: argparse.Namespace) -> int | None:
    """Refuse a mutating command without --yes, unless it is a dry run.

    Returns an exit code when the command must stop, else None.
    ``fix`` and ``restore`` share this gate so the two can never drift
    into different confirmation behavior.
    """
    if not args.yes and not args.dry_run:
        print(
            "Refusing to modify the registry without --yes. "
            "Re-run with --dry-run to preview, or --yes to apply.",
            file=sys.stderr,
        )
        return 2
    return None


def _cmd_check(args: argparse.Namespace, backend: RegistryBackend) -> int:
    """Verify and print. Exit 1 when anything fails or errors."""
    exit_code = 0
    for app in _iter_apps(args.app):
        results = verify_all(load_checks(app, args.data_dir), backend)
        print(format_results(app, results, args.format))
        if any(r.status in ("fail", "error") for r in results):
            exit_code = 1
    return exit_code


def _cmd_list(args: argparse.Namespace) -> int:
    """List bundled checks. Never touches the registry."""
    for app in _iter_apps(args.app):
        print(f"{APPS[app]}:")
        for check in load_checks(app, args.data_dir):
            if check.is_automated:
                if check.pattern is not None:
                    target = (
                        f"{check.hive}\\{check.path}\\{check.value_name} "
                        f"({check.reg_type}) must match pattern {check.pattern!r}"
                    )
                else:
                    target = (
                        f"{check.hive}\\{check.path}\\{check.value_name} "
                        f"({check.reg_type}) = {check.expected!r}"
                    )
            else:
                target = "manual (no registry target)"
            print(f"  {check.id} [{check.severity}] {check.title} -- {target}")
    return 0


def _cmd_fix(args: argparse.Namespace, backend: RegistryBackend) -> int:
    """Apply fixes, or preview them with --dry-run. Exit 1 if any fix fails."""
    refused = _require_confirmation(args)
    if refused is not None:
        return refused
    if os.name == "nt" and not is_admin() and not args.dry_run:
        print(
            "Warning: not running as administrator; registry writes "
            "will likely be denied.",
            file=sys.stderr,
        )
    store = BackupStore(args.backup_dir)
    exit_code = 0
    for app in _iter_apps(args.app):
        checks = load_checks(app, args.data_dir)
        if args.check_id:
            wanted = set(args.check_id)
            checks = [c for c in checks if c.id in wanted]
            missing = wanted - {c.id for c in checks}
            if missing:
                print(
                    f"Unknown check id(s) for {app}: {', '.join(sorted(missing))}",
                    file=sys.stderr,
                )
                return 2
        if args.dry_run:
            results = verify_all(checks, backend)
            # Count only what a real run would write. Failing pattern
            # and manual checks are never auto-fixed, so counting
            # every failure here would promise fixes that never happen.
            fixable = [
                r for r in results if r.status == "fail" and can_auto_fix(r.check)
            ]
            print(
                f"{APPS[app]} dry run: {len(fixable)} failing check(s) "
                "would be fixed, "
                f"{len(results) - len(fixable)} would be left alone. "
                "Nothing was changed."
            )
            for r in fixable:
                print(f"  WOULD FIX {r.check.id}  {r.check.title} ({r.detail})")
            if fixable:
                exit_code = 1
            continue
        outcomes = fix_all(checks, backend, app=app, backup_store=store)
        for outcome in outcomes:
            mark = "FIXED" if outcome.changed else "SKIP"
            if outcome.result.status in ("fail", "error") and not outcome.changed:
                mark = "FAILED"
                exit_code = 1
            print(f"  {mark:6} {outcome.result.check.id}  {outcome.detail}")
    return exit_code


def _cmd_backup(args: argparse.Namespace) -> int:
    """Back up hives with reg save. Exit 1 when a hive backup fails."""
    from .backup import HIVES_TO_BACKUP

    if args.hives:
        wanted = [name.strip().upper() for name in args.hives.split(",")]
        unknown = [name for name in wanted if name not in HIVES_TO_BACKUP]
        if unknown:
            print(
                f"Unknown hive(s): {', '.join(unknown)}; "
                f"expected: {', '.join(HIVES_TO_BACKUP)}",
                file=sys.stderr,
            )
            return 2
        hives = {name: HIVES_TO_BACKUP[name] for name in wanted}
    else:
        hives = None
    try:
        paths = backup_all_hives(args.dir, hives)
    except BackupError as exc:
        print(f"Backup failed: {exc}", file=sys.stderr)
        return 1
    for path in paths:
        print(f"Backed up to {path}")
    return 0


def _cmd_restore(args: argparse.Namespace, backend: RegistryBackend) -> int:
    """Restore per-value backups, or preview them with --dry-run."""
    refused = _require_confirmation(args)
    if refused is not None:
        return refused
    store = BackupStore(args.backup_dir)
    exit_code = 0
    for app_key in _iter_apps(args.app):
        if args.check_id:
            targets = [(app_key, check_id) for check_id in args.check_id]
        else:
            targets = [(app_key, r.check_id) for r in store.latest_for_app(app_key)]
        if not targets:
            print(f"{APPS[app_key]}: no backups recorded in {args.backup_dir}.")
            continue
        for target_app, check_id in targets:
            record = store.latest(target_app, check_id)
            if record is None:
                print(f"  SKIP {check_id}: no backup recorded.")
                continue
            if args.dry_run:
                print(
                    f"  WOULD RESTORE {check_id}: "
                    f"prior existed={record.prior.existed}, "
                    f"value={record.prior.value!r} ({record.prior.reg_type})"
                )
                continue
            try:
                detail = restore_record(backend, record)
            except Exception as exc:  # noqa: BLE001 - report and continue
                print(f"  FAILED {check_id}: {exc}")
                exit_code = 1
                continue
            print(f"  RESTORED {check_id}: {detail}")
    return exit_code


def _cmd_report(args: argparse.Namespace, backend: RegistryBackend) -> int:
    """Verify and print (or write) a report. Exit 1 when anything fails."""
    exit_code = 0
    chunks: list[str] = []
    for app in _iter_apps(args.app):
        results = verify_all(load_checks(app, args.data_dir), backend)
        chunks.append(format_results(app, results, args.format))
        if any(r.status in ("fail", "error") for r in results):
            exit_code = 1
    text = "\n\n".join(chunks) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(text, end="")
    return exit_code


def _cmd_split(args: argparse.Namespace) -> int:
    """Split a concatenated DISA STIG CSV. No registry access needed."""
    input_file: Path = args.input
    output_dir: Path = args.output_dir
    if output_dir is None:
        output_dir = input_file.parent / f"{input_file.stem}_split"
    try:
        summary = split_stig_csv(
            input_file,
            output_dir,
            column=args.column,
            overwrite=args.overwrite,
            dry_run=args.dry_run,
        )
    except SplitError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    verb = "Would write" if args.dry_run else "Wrote"
    print(
        f"{verb} {len(summary.files)} file(s) "
        f"({summary.written_rows} row(s)) to {output_dir}"
    )
    if summary.skipped_rows:
        print(
            f"  Skipped {summary.skipped_rows} row(s) with a blank "
            f"{args.column!r} value."
        )
    for split_file in summary.files:
        print(f"  {split_file.filename}  {split_file.rows} row(s)")
    return 0


def _cmd_gui(args: argparse.Namespace) -> int:
    try:
        from .gui import run_gui  # noqa: PLC0415
    except ImportError:
        print(
            "The GUI needs PyQt6: pip install 'stig-registry-toolkit[gui]' on Windows, "
            "then run 'stig-registry-toolkit gui'.",
            file=sys.stderr,
        )
        return 2
    return run_gui(data_dir=args.data_dir, backup_dir=args.backup_dir, view=args.view)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stig-registry-toolkit",
        description="Check and enforce DISA STIG registry settings (Windows).",
    )
    parser.add_argument(
        "--version", action="version", version=f"{parser.prog} {__version__}"
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        help="Directory holding chrome.json / adobe.json (default: bundled data).",
    )
    parser.add_argument(
        "--view",
        choices=("32", "64"),
        default="64",
        help="Registry view to read and write (default: 64).",
    )
    parser.add_argument(
        "--backup-dir",
        type=Path,
        default=DEFAULT_BACKUP_DIR,
        help="Directory for per-value backups.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="Verify checks against the registry.")
    p_check.add_argument(
        "--app", default="all", help="chrome, adobe, or all (default)."
    )
    p_check.add_argument("--format", choices=("text", "json", "csv"), default="text")
    p_check.set_defaults(func="check")

    p_list = sub.add_parser(
        "list", help="List bundled checks without touching the registry."
    )
    p_list.add_argument("--app", default="all", help="chrome, adobe, or all (default).")
    p_list.set_defaults(func="list")

    p_fix = sub.add_parser("fix", help="Apply fixes for failing checks (needs --yes).")
    p_fix.add_argument("--app", default="all", help="chrome, adobe, or all (default).")
    p_fix.add_argument(
        "--check-id",
        action="append",
        default=[],
        help="Fix only this check id (repeatable).",
    )
    p_fix.add_argument(
        "--dry-run", action="store_true", help="Preview only; change nothing."
    )
    p_fix.add_argument("--yes", action="store_true", help="Confirm registry changes.")
    # Also accepted after the subcommand; SUPPRESS keeps the global value.
    p_fix.add_argument(
        "--backup-dir",
        type=Path,
        default=argparse.SUPPRESS,
        help="Directory for per-value backups.",
    )
    p_fix.set_defaults(func="fix")

    p_backup = sub.add_parser("backup", help="Back up registry hives with reg save.")
    p_backup.add_argument(
        "--dir", type=Path, default=DEFAULT_BACKUP_DIR, help="Destination directory."
    )
    p_backup.add_argument(
        "--hives",
        default="",
        help="Comma list: SYSTEM,SOFTWARE,CURRENT_USER (default: all).",
    )
    p_backup.set_defaults(func="backup")

    p_restore = sub.add_parser("restore", help="Restore values from per-value backups.")
    p_restore.add_argument(
        "--app", default="all", help="chrome, adobe, or all (default)."
    )
    p_restore.add_argument(
        "--check-id",
        action="append",
        default=[],
        help="Restore only this check id (repeatable).",
    )
    p_restore.add_argument(
        "--dry-run", action="store_true", help="Preview only; change nothing."
    )
    p_restore.add_argument(
        "--yes", action="store_true", help="Confirm registry changes."
    )
    p_restore.add_argument(
        "--backup-dir",
        type=Path,
        default=argparse.SUPPRESS,
        help="Directory for per-value backups.",
    )
    p_restore.set_defaults(func="restore")

    p_report = sub.add_parser("report", help="Verify and write a report.")
    p_report.add_argument(
        "--app", default="all", help="chrome, adobe, or all (default)."
    )
    p_report.add_argument("--format", choices=("text", "json", "csv"), default="text")
    p_report.add_argument(
        "--output", type=Path, default=None, help="Write report to this file."
    )
    p_report.set_defaults(func="report")

    p_split = sub.add_parser(
        "split",
        help="Split a concatenated DISA STIG CSV into one file per STIG title.",
    )
    p_split.add_argument(
        "input", type=Path, help="Concatenated DISA STIG CSV to split."
    )
    p_split.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Destination directory (default: <input-stem>_split next to the input).",
    )
    p_split.add_argument(
        "--column",
        default="STIG",
        help="Column to split on (default: STIG).",
    )
    p_split.add_argument(
        "--dry-run", action="store_true", help="Preview only; write nothing."
    )
    p_split.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace existing output files (default: refuse).",
    )
    p_split.set_defaults(func="split")

    p_gui = sub.add_parser("gui", help="Open the graphical interface (needs PyQt6).")
    p_gui.set_defaults(func="gui")

    return parser


def main(
    argv: list[str] | None = None,
    backend: RegistryBackend | None = None,
) -> int:
    """Entry point. ``backend`` is injectable for tests; callers in
    production leave it None to get the real Windows backend."""
    args = build_parser().parse_args(argv)
    try:
        if args.func == "list":
            return _cmd_list(args)
        if args.func == "backup":
            return _cmd_backup(args)
        if args.func == "gui":
            return _cmd_gui(args)
        if args.func == "split":
            return _cmd_split(args)
        real_backend = _require_backend(backend, args.view)
        if args.func == "check":
            return _cmd_check(args, real_backend)
        if args.func == "fix":
            return _cmd_fix(args, real_backend)
        if args.func == "restore":
            return _cmd_restore(args, real_backend)
        if args.func == "report":
            return _cmd_report(args, real_backend)
    except RegistryUnavailableError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except BackupError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        # Report writes, backup directories, and other filesystem
        # failures must fail as a clean error, not a traceback.
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
