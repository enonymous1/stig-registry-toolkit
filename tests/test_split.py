"""Tests for the STIG CSV splitter (no registry, no real DISA data)."""

import csv
from pathlib import Path

import pytest

from stig_registry_toolkit.cli import main
from stig_registry_toolkit.split import (
    SplitError,
    _assign_filenames,
    _sanitize_stem,
    split_stig_csv,
)

HEADER = ["STIG", "Vuln ID", "Rule Title"]


def _write_csv(path: Path, rows: list[list[str]]) -> Path:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(HEADER)
        writer.writerows(rows)
    return path


def _read_csv(path: Path) -> list[list[str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.reader(handle))


def test_split_basic(tmp_path: Path):
    src = _write_csv(
        tmp_path / "all.csv",
        [
            ["Alpha", "V-1", "First"],
            ["Beta", "V-2", "Second"],
            ["Alpha", "V-3", "Third"],
        ],
    )
    out = tmp_path / "out"
    summary = split_stig_csv(src, out)
    assert summary.total_rows == 3
    assert summary.skipped_rows == 0
    assert summary.written_rows == 3
    assert {f.filename for f in summary.files} == {"Alpha.csv", "Beta.csv"}
    assert _read_csv(out / "Alpha.csv") == [
        HEADER,
        ["Alpha", "V-1", "First"],
        ["Alpha", "V-3", "Third"],
    ]
    assert _read_csv(out / "Beta.csv") == [HEADER, ["Beta", "V-2", "Second"]]


def test_split_many_groups_exceeds_writer_cache(tmp_path: Path):
    # 40 groups > _MAX_OPEN_WRITERS (32): eviction/reopen must not
    # lose rows or duplicate headers.
    rows = [[f"Group {i:02d}", f"V-{i}", "x"] for i in range(40) for _ in range(3)]
    src = _write_csv(tmp_path / "all.csv", rows)
    summary = split_stig_csv(src, tmp_path / "out")
    assert len(summary.files) == 40
    assert summary.written_rows == 120
    for i in range(40):
        data = _read_csv(tmp_path / "out" / f"Group {i:02d}.csv")
        assert data[0] == HEADER
        assert len(data) == 4


def test_collision_gets_distinct_filenames(tmp_path: Path):
    # The original script lost one of these: both sanitize to A_B.csv.
    src = _write_csv(
        tmp_path / "all.csv",
        [["A/B", "V-1", "slash"], ["A_B", "V-2", "underscore"]],
    )
    summary = split_stig_csv(src, tmp_path / "out")
    filenames = {f.filename for f in summary.files}
    assert filenames == {"A_B.csv", "A_B__2.csv"}
    contents = {name: _read_csv(tmp_path / "out" / name) for name in filenames}
    assert sorted(row[1] for rows in contents.values() for row in rows[1:]) == [
        "V-1",
        "V-2",
    ]
    assert _assign_filenames(["A/B", "A_B", "A:B"]) == {
        "A/B": "A_B.csv",
        "A_B": "A_B__2.csv",
        "A:B": "A_B__3.csv",
    }


def test_blank_group_skipped_not_dot_csv(tmp_path: Path):
    src = _write_csv(
        tmp_path / "all.csv",
        [["Alpha", "V-1", "ok"], ["", "V-2", "blank"], ["   ", "V-3", "spaces"]],
    )
    summary = split_stig_csv(src, tmp_path / "out")
    assert summary.skipped_rows == 2
    assert summary.total_rows == 3
    assert not (tmp_path / "out" / ".csv").exists()
    assert [f.filename for f in summary.files] == ["Alpha.csv"]


def test_reserved_and_dotty_stems(tmp_path: Path):
    assert _sanitize_stem("CON") == "_CON"
    assert _sanitize_stem("...") == "_"
    assert _sanitize_stem("a/b:c") == "a_b_c"
    assert _sanitize_stem("trailing. ") == "trailing"


def test_dry_run_writes_nothing(tmp_path: Path):
    src = _write_csv(tmp_path / "all.csv", [["Alpha", "V-1", "x"]])
    out = tmp_path / "out"
    summary = split_stig_csv(src, out, dry_run=True)
    assert summary.dry_run is True
    assert summary.files[0].filename == "Alpha.csv"
    assert not out.exists()


def test_existing_output_refused_without_overwrite(tmp_path: Path):
    src = _write_csv(tmp_path / "all.csv", [["Alpha", "V-1", "x"]])
    out = tmp_path / "out"
    split_stig_csv(src, out)
    with pytest.raises(SplitError, match="refusing to overwrite"):
        split_stig_csv(src, out)
    # The refused run must not have truncated the good output.
    assert _read_csv(out / "Alpha.csv")[1] == ["Alpha", "V-1", "x"]
    split_stig_csv(src, out, overwrite=True)
    assert _read_csv(out / "Alpha.csv")[1] == ["Alpha", "V-1", "x"]


def test_custom_column(tmp_path: Path):
    src = _write_csv(
        tmp_path / "all.csv",
        [["Alpha", "V-1", "x"], ["Beta", "V-2", "y"]],
    )
    summary = split_stig_csv(src, tmp_path / "out", column="Vuln ID")
    assert {f.filename for f in summary.files} == {"V-1.csv", "V-2.csv"}


def test_errors(tmp_path: Path):
    with pytest.raises(SplitError, match="not found"):
        split_stig_csv(tmp_path / "missing.csv", tmp_path / "out")
    header_only = tmp_path / "header.csv"
    header_only.write_text("STIG,Vuln ID\n", encoding="utf-8")
    with pytest.raises(SplitError, match="no data rows"):
        split_stig_csv(header_only, tmp_path / "out")
    src = _write_csv(tmp_path / "all.csv", [["Alpha", "V-1", "x"]])
    with pytest.raises(SplitError, match="no column 'Nope'"):
        split_stig_csv(src, tmp_path / "out", column="Nope")
    # Row with more fields than the header fails loudly.
    bad = tmp_path / "bad.csv"
    bad.write_text("STIG,Vuln ID\nAlpha,V-1,extra\n", encoding="utf-8")
    with pytest.raises(SplitError, match="more fields"):
        split_stig_csv(bad, tmp_path / "out")


def test_cli_split_no_registry_needed(tmp_path: Path, capsys):
    src = _write_csv(
        tmp_path / "all.csv",
        [["A/B", "V-1", "slash"], ["A_B", "V-2", "underscore"]],
    )
    # No backend passed: split must not touch (or require) the registry.
    code = main(["split", str(src), "--output-dir", str(tmp_path / "out")])
    assert code == 0
    out = capsys.readouterr().out
    assert "2 file(s)" in out
    assert "A_B__2.csv" in out
    assert len(list((tmp_path / "out").glob("*.csv"))) == 2


def test_cli_split_dry_run_and_default_output_dir(tmp_path: Path, capsys):
    src = _write_csv(tmp_path / "all.csv", [["Alpha", "V-1", "x"]])
    code = main(["split", str(src), "--dry-run"])
    assert code == 0
    # Default output dir is <stem>_split next to the input; dry run
    # must not create it.
    assert not (tmp_path / "all_split").exists()
    assert "Would write" in capsys.readouterr().out


def test_cli_split_missing_file_is_usage_error(capsys):
    code = main(["split", "no-such-file.csv"])
    assert code == 2
    assert "not found" in capsys.readouterr().err
