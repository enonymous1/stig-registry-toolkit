"""Shipped-data integrity: no stale results, no drifted field names."""

import json
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "src" / "stig_registry_toolkit" / "data"


def test_data_files_have_no_result_fields():
    for name in ("chrome.json", "adobe.json"):
        text = (DATA / name).read_text(encoding="utf-8")
        assert "ruleResult" not in text
        assert "resultFixed" not in text
        assert "Pass (Verified)" not in text
        doc = json.loads(text)
        assert doc["schema_version"] == 1
        assert all(
            set(c)
            == {
                "id",
                "title",
                "severity",
                "test_type",
                "description",
                "fix_text",
                "reference",
                "rule_id",
                "hive",
                "path",
                "value_name",
                "reg_type",
                "expected",
                "pattern",
            }
            for c in doc["checks"]
        )


def test_data_text_is_nonempty_and_ids_well_formed():
    import re

    for name in ("chrome.json", "adobe.json"):
        doc = json.loads((DATA / name).read_text(encoding="utf-8"))
        for check in doc["checks"]:
            assert re.match(r"^V-\d+$", check["id"])
            assert check["title"].strip()
            assert check["description"].strip()
            assert check["fix_text"].strip()
            assert check["severity"] in ("low", "medium", "high")
