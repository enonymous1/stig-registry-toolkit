# Changelog

## 2.1.0 — 2026-10-28

Folded in the standalone STIG CSV splitter (`stigs`, 2026-07-19):
`stig-registry-toolkit split` splits a concatenated DISA STIG export
into one CSV per STIG title. The bundled Chrome/Adobe check data was
derived from such an export (the export's 42 Chrome rows match the
42 bundled Chrome checks), so the prep step now lives with the tool
that consumes it. The 46 MB export itself is not shipped; bring your
own current DISA export.

- New `split` subcommand (no registry access): `split all_stigs.csv`
  writes `<stem>_split/<STIG>.csv` files, `--output-dir` overrides,
  `--column` picks the split column (default `STIG`), `--dry-run`
  previews counts without writing, and existing outputs block the
  run unless `--overwrite` is given.
- Fixes the original script's bugs: colliding sanitized titles get
  distinct filenames (`A/B` vs `A_B`) instead of overwriting each
  other, blank titles are skipped and counted instead of writing
  `.csv`, outputs are streamed through a bounded writer cache
  instead of holding all 402 files open, malformed rows fail
  loudly, and Windows reserved stems (`CON`, `PRN`, ...) are
  prefixed. 12 new tests; 60 total.

## 2.0.0 — 2026-10-27

Renamed to stig-registry-toolkit before publication; the
pre-publication export was named ss-sec, the modernization of the
original SS-SEC prototype.

Complete rewrite of the 1.x flat-script tool. Breaking changes throughout;
1.x check files and the 1.x entry points do not carry over.

- One canonical check schema for both apps. The Chrome data is
  normalized from the 1.x JSON shape (`hive`/`key`/`name`/`type`/`value`)
  into the same shape Adobe already used, with the two manual-only
  checks from the old constants file (V-221584, V-221596) restored.
  The old `google_chrome_constants.py` duplicate (42 entries, drifted
  titles and two misspelled value names, `SafeBrowse*` for
  `SafeBrowsing*`) is deleted; the JSON spellings are kept.
- Results are no longer stored in the data files. Status is always
  computed live against the registry, so the shipped files cannot
  claim a machine is compliant because another machine once passed.
  The stale `Pass (Verified)` results stamped 2025-05-11 are gone.
- New installable package (`stig_registry_toolkit`) with a CLI: `check`, `fix`,
  `backup`, `restore`, `report`, `list`, and `gui`. The GUI drops the
  WebEngine table for a native table; PyQt6-WebEngine is no longer
  needed.
- Fixes are safe by default: `fix` needs `--yes` (or `--dry-run`),
  records the prior value before writing, re-verifies after writing,
  and can be undone with `restore`. Pattern checks and manual checks
  are never auto-fixed. Multi-value checks accept any listed value
  and fix to the first one.
- Reads and writes use the same registry view (64-bit by default,
  `--view 32` to change it). Leading-backslash paths are normalized
  on both read and write.
- The dead Qt panel (`base_panel_qt.py` / `google_chrome_panel_qt.py`,
  which faked results and never touched the registry) and the
  manual `registry_test.py` script are deleted, replaced by a pytest
  suite against an in-memory registry backend.
- Python 3.10+, pinned dev gates (ruff, mypy on the core modules,
  pytest), GitHub Actions CI on Ubuntu and Windows, MIT LICENSE.

## 1.x

Single-commit prototype (2026-07-19): PyQt6 panels over `winreg`
with bundled Chrome and Adobe STIG JSON files and `reg save` hive
backup. Chrome enforcement never ran (schema mismatch); Adobe
results were stale snapshots. See the audit notes in the 2.0.0
entry above.
