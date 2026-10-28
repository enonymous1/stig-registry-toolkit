"""Split a concatenated DISA STIG CSV into one file per STIG title.

This is the prep step the bundled Chrome/Adobe check data came from:
a DISA export concatenates every benchmark into one CSV, and this
module splits it back into one CSV per value in a chosen column
(``STIG`` by default). It writes CSVs only; it does not convert a
split file into the JSON check schema in ``checks.py``.

Unlike the original 58-line script this replaces, splitting here:

* plans first, so a dry run reports every file and row count without
  writing anything, and existing outputs block the run unless
  ``--overwrite`` is given;
* streams both passes, so exports far larger than the bundled 46 MB
  example are never held in memory as a group;
* never holds every output file open at once (a bounded writer
  cache, reopened in append mode), so a 402-benchmark export does
  not sit near the per-process open-file limit;
* gives colliding titles distinct filenames instead of silently
  overwriting one with the other (``A/B`` and ``A_B`` are different
  benchmarks and must stay different files);
* skips rows whose group value is blank instead of writing ``.csv``,
  and fails loudly on malformed rows instead of dropping columns.
"""

from __future__ import annotations

import csv
import re
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

# Windows reserved device names: a file named ``CON.csv`` cannot be
# created, whatever the STIG title says.
_RESERVED_STEMS = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *[f"COM{i}" for i in range(1, 10)],
        *[f"LPT{i}" for i in range(1, 10)],
    }
)
_INVALID_CHARS = re.compile(r'[\\/:*?"<>|\x00-\x1f]')
_MAX_STEM = 100
_MAX_OPEN_WRITERS = 32


class SplitError(ValueError):
    """A split cannot run (or cannot finish) for the stated reason."""


@dataclass(frozen=True)
class SplitFile:
    """One output file: the group value it holds and its row count."""

    group: str
    filename: str
    rows: int


@dataclass(frozen=True)
class SplitSummary:
    """The outcome of a split (or a dry run of one)."""

    input_file: Path
    output_dir: Path
    column: str
    total_rows: int
    skipped_rows: int
    files: tuple[SplitFile, ...]
    dry_run: bool

    @property
    def written_rows(self) -> int:
        return sum(f.rows for f in self.files)


def _sanitize_stem(group: str) -> str:
    """Make ``group`` safe as a filename stem on Windows and POSIX."""
    stem = _INVALID_CHARS.sub("_", group).strip().rstrip(". ")
    if not stem:
        stem = "_"
    stem = stem[:_MAX_STEM].rstrip(". ")
    if not stem:
        stem = "_"
    if stem.upper() in _RESERVED_STEMS:
        stem = f"_{stem}"
    return stem


def _assign_filenames(groups: list[str]) -> dict[str, str]:
    """Map each group value to a distinct ``<stem>.csv`` filename.

    Filenames are assigned in first-seen order; a later group whose
    sanitized stem is already taken gets ``__2``, ``__3``, ... so no
    group's rows ever overwrite another's.
    """
    claimed: dict[str, str] = {}
    assigned: dict[str, str] = {}
    for group in groups:
        stem = _sanitize_stem(group)
        candidate = f"{stem}.csv"
        suffix = 2
        while candidate in claimed and claimed[candidate] != group:
            candidate = f"{stem}__{suffix}.csv"
            suffix += 1
        claimed[candidate] = group
        assigned[group] = candidate
    return assigned


def _open_reader(
    input_file: Path, column: str
) -> tuple[TextIO, csv.DictReader[str], list[str]]:
    """Open ``input_file`` and validate its header for ``column``.

    The caller owns the returned handle and must close it. Raises
    :class:`SplitError` on an unreadable file, an empty file, or a
    missing column.
    """
    try:
        handle = input_file.open(newline="", encoding="utf-8")
    except OSError as exc:
        raise SplitError(f"cannot read {input_file}: {exc}") from exc
    reader = csv.DictReader(handle)
    fieldnames: list[str] = list(reader.fieldnames or [])
    if not fieldnames:
        handle.close()
        raise SplitError(f"{input_file}: no header row found")
    if column not in fieldnames:
        handle.close()
        raise SplitError(
            f"{input_file}: no column {column!r}; columns are: {', '.join(fieldnames)}"
        )
    return handle, reader, fieldnames


def _count_rows(
    reader: csv.DictReader[str],
    input_file: Path,
    column: str,
) -> tuple[list[str], dict[str, int], int, int]:
    """Stream the planning pass, counting rows per group value.

    Returns ``(fieldnames, counts, total_rows, skipped_rows)`` where
    ``counts`` is in first-seen order and ``skipped_rows`` counts rows
    whose group value is blank. Raises :class:`SplitError` on a row
    with extra fields or malformed CSV content.
    """
    fieldnames = list(reader.fieldnames or [])
    counts: dict[str, int] = {}
    skipped = 0
    total = 0
    try:
        for row in reader:
            total += 1
            if None in row:
                raise SplitError(
                    f"{input_file}:{reader.line_num}: row has more fields "
                    f"than the header ({len(fieldnames)} columns)"
                )
            value = row.get(column)
            group = value.strip() if value else ""
            if not group:
                skipped += 1
                continue
            counts[group] = counts.get(group, 0) + 1
    except csv.Error as exc:
        raise SplitError(f"{input_file}: malformed CSV: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise SplitError(f"{input_file}: not valid UTF-8: {exc}") from exc
    return fieldnames, counts, total, skipped


class _WriterCache:
    """At most ``_MAX_OPEN_WRITERS`` output files open at once.

    Evicted writers are closed and reopened in append mode on their
    next row; the header is written only on a file's first open.
    """

    def __init__(self, output_dir: Path, fieldnames: list[str]) -> None:
        self._output_dir = output_dir
        self._fieldnames = fieldnames
        self._writers: OrderedDict[str, tuple[Any, TextIO]] = OrderedDict()
        self._started: set[str] = set()

    def write(self, filename: str, row: list[str]) -> None:
        entry = self._writers.get(filename)
        if entry is None:
            if len(self._writers) >= _MAX_OPEN_WRITERS:
                _, (_, handle) = self._writers.popitem(last=False)
                handle.close()
            first_open = filename not in self._started
            handle = (self._output_dir / filename).open(
                "w" if first_open else "a", newline="", encoding="utf-8"
            )
            writer = csv.writer(handle)
            if first_open:
                writer.writerow(self._fieldnames)
                self._started.add(filename)
            entry = (writer, handle)
            self._writers[filename] = entry
        else:
            self._writers.move_to_end(filename)
        entry[0].writerow(row)

    def close(self) -> None:
        for _, handle in self._writers.values():
            handle.close()
        self._writers.clear()


def split_stig_csv(
    input_file: Path,
    output_dir: Path,
    *,
    column: str = "STIG",
    overwrite: bool = False,
    dry_run: bool = False,
) -> SplitSummary:
    """Split ``input_file`` by ``column`` into ``output_dir``.

    The input is read twice: once to plan (counts, filenames, and
    existing-output checks), once to write. Both passes stream, so
    no group of rows is ever held in memory.
    """
    input_file = Path(input_file)
    output_dir = Path(output_dir)
    if not input_file.is_file():
        raise SplitError(f"input file not found: {input_file}")

    handle, reader, fieldnames = _open_reader(input_file, column)
    try:
        _fieldnames, counts, total_rows, skipped = _count_rows(
            reader, input_file, column
        )
    finally:
        handle.close()
    if not counts:
        raise SplitError(
            f"{input_file}: no data rows with a {column!r} value "
            f"({total_rows} row(s) read, {skipped} skipped as blank)"
        )
    filenames = _assign_filenames(list(counts))
    files = tuple(
        SplitFile(group=group, filename=filenames[group], rows=rows)
        for group, rows in counts.items()
    )
    summary = SplitSummary(
        input_file=input_file,
        output_dir=output_dir,
        column=column,
        total_rows=total_rows,
        skipped_rows=skipped,
        files=files,
        dry_run=dry_run,
    )
    if dry_run:
        return summary
    existing = [f.filename for f in files if (output_dir / f.filename).exists()]
    if existing and not overwrite:
        shown = ", ".join(existing[:5])
        extra = f" and {len(existing) - 5} more" if len(existing) > 5 else ""
        raise SplitError(
            f"refusing to overwrite existing output file(s) in {output_dir}: "
            f"{shown}{extra}. Re-run with --overwrite to replace them."
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    handle, reader, fieldnames = _open_reader(input_file, column)
    cache = _WriterCache(output_dir, fieldnames)
    try:
        try:
            for row in reader:
                if None in row:
                    raise SplitError(
                        f"{input_file}:{reader.line_num}: row has more fields "
                        f"than the header ({len(fieldnames)} columns)"
                    )
                value = row.get(column)
                group = value.strip() if value else ""
                if not group:
                    continue
                filename = filenames.get(group)
                if filename is None:
                    raise SplitError(
                        f"{input_file}: {column!r} value {group!r} appeared "
                        "during writing but not during planning; the input "
                        "file may have changed mid-split"
                    )
                cache.write(
                    filename,
                    ["" if row.get(name) is None else row[name] for name in fieldnames],
                )
        except csv.Error as exc:
            raise SplitError(f"{input_file}: malformed CSV: {exc}") from exc
        except UnicodeDecodeError as exc:
            raise SplitError(f"{input_file}: not valid UTF-8: {exc}") from exc
    finally:
        cache.close()
        handle.close()
    return summary
